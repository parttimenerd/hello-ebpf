/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with vcap
 */
@java.lang.SuppressWarnings("unused")
public final class VcapDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean _vcap_rule_find_keysets(Ptr<vcap_rule_internal> ri,
      Ptr<vcap_keyset_list> matches) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_actionfield_count(Ptr<vcap_control> vctrl, vcap_type vt,
      vcap_actionfield_set actionset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)vcap_actionfield_name($arg1, $arg2))")
  public static String vcap_actionfield_name(Ptr<vcap_control> vctrl, vcap_action_field action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct vcap_typegroup*)vcap_actionfield_typegroup($arg1, $arg2, $arg3))")
  public static Ptr<vcap_typegroup> vcap_actionfield_typegroup(Ptr<vcap_control> vctrl,
      vcap_type vt, vcap_actionfield_set actionset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct vcap_field*)vcap_actionfields($arg1, $arg2, $arg3))")
  public static Ptr<vcap_field> vcap_actionfields(Ptr<vcap_control> vctrl, vcap_type vt,
      vcap_actionfield_set actionset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct vcap_set*)vcap_actionfieldset($arg1, $arg2, $arg3))")
  public static Ptr<vcap_set> vcap_actionfieldset(Ptr<vcap_control> vctrl, vcap_type vt,
      vcap_actionfield_set actionset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)vcap_actionset_name($arg1, $arg2))")
  public static String vcap_actionset_name(Ptr<vcap_control> vctrl,
      vcap_actionfield_set actionset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_add_rule(Ptr<vcap_rule> rule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_addr_keysets(Ptr<vcap_control> vctrl, Ptr<net_device> ndev,
      Ptr<vcap_admin> admin, int addr, Ptr<vcap_keyset_list> kslist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_admin_rule_count(Ptr<vcap_admin> admin, int cid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vcap_rule> vcap_alloc_rule(Ptr<vcap_control> vctrl, Ptr<net_device> ndev,
      int vcap_chain_id, vcap_user user, @Unsigned short priority, @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_api_check(Ptr<vcap_control> ctrl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vcap_bitarray_zero(int width, Ptr<java.lang.Character> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_chain_id_to_lookup(Ptr<vcap_admin> admin, int cur_cid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_chain_offset(Ptr<vcap_control> vctrl, int from_cid, int to_cid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_copy_from_client_actionfield($arg1, $arg2, (const struct vcap_client_actionfield *)$arg3)")
  public static void vcap_copy_from_client_actionfield(Ptr<vcap_rule> rule,
      Ptr<vcap_client_actionfield> dst, Ptr<vcap_client_actionfield> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_copy_from_client_keyfield($arg1, $arg2, (const struct vcap_client_keyfield *)$arg3)")
  public static void vcap_copy_from_client_keyfield(Ptr<vcap_rule> rule,
      Ptr<vcap_client_keyfield> dst, Ptr<vcap_client_keyfield> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_copy_from_w32be(Ptr<java.lang.Character> dst,
      Ptr<java.lang.Character> src, int size, int width) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_copy_limited_actionfield(Ptr<java.lang.Character> dstvalue,
      Ptr<java.lang.Character> srcvalue, int width, int bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_copy_limited_keyfield(Ptr<java.lang.Character> dstvalue,
      Ptr<java.lang.Character> dstmask, Ptr<java.lang.Character> srcvalue,
      Ptr<java.lang.Character> srcmask, int width, int bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vcap_rule> vcap_copy_rule(Ptr<vcap_rule> erule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_copy_to_client_actionfield(Ptr<vcap_rule_internal> ri,
      Ptr<vcap_client_actionfield> field, Ptr<java.lang.Character> value, @Unsigned short width) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_copy_to_client_keyfield(Ptr<vcap_rule_internal> ri,
      Ptr<vcap_client_keyfield> field, Ptr<java.lang.Character> value,
      Ptr<java.lang.Character> mask, @Unsigned short width) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> vcap_debugfs(Ptr<device> dev, Ptr<dentry> parent,
      Ptr<vcap_control> vctrl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_debugfs_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_debugfs_show(Ptr<seq_file> m, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_debugfs_show_rule_actionfield($arg1, $arg2, $arg3, (const struct vcap_field *)$arg4, $arg5)")
  public static void vcap_debugfs_show_rule_actionfield(Ptr<vcap_control> vctrl,
      Ptr<vcap_output_print> out, vcap_action_field action, Ptr<vcap_field> actionfield,
      Ptr<java.lang.Character> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_debugfs_show_rule_keyfield($arg1, $arg2, $arg3, (const struct vcap_field *)$arg4, $arg5)")
  public static void vcap_debugfs_show_rule_keyfield(Ptr<vcap_control> vctrl,
      Ptr<vcap_output_print> out, vcap_key_field key, Ptr<vcap_field> keyfield,
      Ptr<vcap_client_keyfield_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_debugfs_show_rule_keyset(Ptr<vcap_rule_internal> ri,
      Ptr<vcap_output_print> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_decode_actionset(Ptr<vcap_rule_internal> ri) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_decode_field(Ptr<java.lang. @Unsigned Integer> stream,
      Ptr<vcap_stream_iter> itr, int width, Ptr<java.lang.Character> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_decode_keyset(Ptr<vcap_rule_internal> ri) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vcap_rule> vcap_decode_rule(Ptr<vcap_rule_internal> elem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_del_rule(Ptr<vcap_control> vctrl, Ptr<net_device> ndev, @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_del_rules(Ptr<vcap_control> vctrl, Ptr<vcap_admin> admin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_disable(Ptr<vcap_control> vctrl, Ptr<net_device> ndev,
      @Unsigned long cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vcap_rule_internal> vcap_dup_rule(Ptr<vcap_rule_internal> ri, boolean full) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_enable(Ptr<vcap_control> vctrl, Ptr<net_device> ndev,
      @Unsigned long cookie, int src_cid, int dst_cid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_enable_lookups(Ptr<vcap_control> vctrl, Ptr<net_device> ndev, int src_cid,
      int dst_cid, @Unsigned long cookie, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_encode_field($arg1, $arg2, $arg3, (const u8 *)$arg4)")
  public static void vcap_encode_field(Ptr<java.lang. @Unsigned Integer> stream,
      Ptr<vcap_stream_iter> itr, int width, Ptr<java.lang.Character> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_encode_rule_actionset(Ptr<vcap_rule_internal> ri) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_encode_rule_keyset(Ptr<vcap_rule_internal> ri) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_encode_typegroups($arg1, $arg2, (const struct vcap_typegroup *)$arg3, $arg4)")
  public static void vcap_encode_typegroups(Ptr<java.lang. @Unsigned Integer> stream, int sw_width,
      Ptr<vcap_typegroup> tg, boolean mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_erase_cache(Ptr<vcap_rule_internal> ri) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_filter_rule_keys(Ptr<vcap_rule> rule, Ptr<vcap_key_field> keylist,
      int length, boolean drop_unsupported) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vcap_client_actionfield> vcap_find_actionfield(Ptr<vcap_rule> rule,
      vcap_action_field act) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vcap_admin> vcap_find_admin(Ptr<vcap_control> vctrl, int cid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_find_keystream_keysets(Ptr<vcap_control> vctrl, vcap_type vt,
      Ptr<java.lang. @Unsigned Integer> keystream, Ptr<java.lang. @Unsigned Integer> mskstream,
      boolean mask, int sw_max, Ptr<vcap_keyset_list> kslist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_free_rule(Ptr<vcap_rule> rule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vcap_rule> vcap_get_rule(Ptr<vcap_control> vctrl, @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_get_rule_count_by_cookie(Ptr<vcap_control> vctrl, Ptr<vcap_counter> ctr,
      @Unsigned long cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_insert_rule(Ptr<vcap_rule_internal> ri, Ptr<vcap_rule_move> move) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vcap_is_last_chain(Ptr<vcap_control> vctrl, int cid, boolean ingress) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vcap_is_next_lookup(Ptr<vcap_control> vctrl, int src_cid, int dst_cid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_iter_init($arg1, $arg2, (const struct vcap_typegroup *)$arg3, $arg4)")
  public static void vcap_iter_init(Ptr<vcap_stream_iter> itr, int sw_width, Ptr<vcap_typegroup> tg,
      @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_iter_next(Ptr<vcap_stream_iter> itr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_iter_set($arg1, $arg2, (const struct vcap_typegroup *)$arg3, $arg4)")
  public static void vcap_iter_set(Ptr<vcap_stream_iter> itr, int sw_width, Ptr<vcap_typegroup> tg,
      @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_iter_update(Ptr<vcap_stream_iter> itr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_keyfield_count(Ptr<vcap_control> vctrl, vcap_type vt,
      vcap_keyfield_set keyset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)vcap_keyfield_name($arg1, $arg2))")
  public static String vcap_keyfield_name(Ptr<vcap_control> vctrl, vcap_key_field key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct vcap_typegroup*)vcap_keyfield_typegroup($arg1, $arg2, $arg3))")
  public static Ptr<vcap_typegroup> vcap_keyfield_typegroup(Ptr<vcap_control> vctrl, vcap_type vt,
      vcap_keyfield_set keyset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct vcap_field*)vcap_keyfields($arg1, $arg2, $arg3))")
  public static Ptr<vcap_field> vcap_keyfields(Ptr<vcap_control> vctrl, vcap_type vt,
      vcap_keyfield_set keyset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct vcap_set*)vcap_keyfieldset($arg1, $arg2, $arg3))")
  public static Ptr<vcap_set> vcap_keyfieldset(Ptr<vcap_control> vctrl, vcap_type vt,
      vcap_keyfield_set keyset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vcap_keyset_list_add(Ptr<vcap_keyset_list> keysetlist,
      vcap_keyfield_set keyset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)vcap_keyset_name($arg1, $arg2))")
  public static String vcap_keyset_name(Ptr<vcap_control> vctrl, vcap_keyfield_set keyset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct vcap_field*)vcap_lookup_keyfield($arg1, $arg2))")
  public static Ptr<vcap_field> vcap_lookup_keyfield(Ptr<vcap_rule> rule, vcap_key_field key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_lookup_rule_by_cookie(Ptr<vcap_control> vctrl, @Unsigned long cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_mod_rule(Ptr<vcap_rule> rule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_netbytes_copy(Ptr<java.lang.Character> dst, Ptr<java.lang.Character> src,
      int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vcap_path_exist(Ptr<vcap_control> vctrl, Ptr<net_device> ndev,
      int dst_cid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_port_debugfs(Ptr<device> dev, Ptr<dentry> parent, Ptr<vcap_control> vctrl,
      Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_port_debugfs_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_port_debugfs_show(Ptr<seq_file> m, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_raw_debugfs_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_raw_debugfs_show(Ptr<seq_file> m, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_read_counter(Ptr<vcap_rule_internal> ri, Ptr<vcap_counter> ctr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_read_rule(Ptr<vcap_rule_internal> ri) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_action(Ptr<vcap_rule> rule, vcap_action_field action,
      vcap_field_type ftype, Ptr<vcap_client_actionfield_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_action_bit(Ptr<vcap_rule> rule, vcap_action_field action,
      vcap_bit val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_action_u32(Ptr<vcap_rule> rule, vcap_action_field action,
      @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_action_u72(Ptr<vcap_rule> rule, vcap_action_field action,
      Ptr<vcap_u72_action> fieldval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_key(Ptr<vcap_rule> rule, vcap_key_field key,
      vcap_field_type ftype, Ptr<vcap_client_keyfield_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_key_bit(Ptr<vcap_rule> rule, vcap_key_field key, vcap_bit val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_key_u128(Ptr<vcap_rule> rule, vcap_key_field key,
      Ptr<vcap_u128_key> fieldval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_key_u32(Ptr<vcap_rule> rule, vcap_key_field key,
      @Unsigned int value, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_key_u48(Ptr<vcap_rule> rule, vcap_key_field key,
      Ptr<vcap_u48_key> fieldval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_add_key_u72(Ptr<vcap_rule> rule, vcap_key_field key,
      Ptr<vcap_u72_key> fieldval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean vcap_rule_find_keysets(Ptr<vcap_rule> rule, Ptr<vcap_keyset_list> matches) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_get_counter(Ptr<vcap_rule> rule, Ptr<vcap_counter> ctr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_get_key_u32(Ptr<vcap_rule> rule, vcap_key_field key,
      Ptr<java.lang. @Unsigned Integer> value, Ptr<java.lang. @Unsigned Integer> mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_get_keysets(Ptr<vcap_rule_internal> ri,
      Ptr<vcap_keyset_list> matches) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_mod_action_u32(Ptr<vcap_rule> rule, vcap_action_field action,
      @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_mod_key_u32(Ptr<vcap_rule> rule, vcap_key_field key,
      @Unsigned int value, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_rem_key(Ptr<vcap_rule> rule, vcap_key_field key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_rule_set_counter(Ptr<vcap_rule> rule, Ptr<vcap_counter> ctr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_rule_set_counter_id(Ptr<vcap_rule> rule, @Unsigned int counter_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static vcap_keyfield_set vcap_select_min_rule_keyset(Ptr<vcap_control> vctrl,
      vcap_type vtype, Ptr<vcap_keyset_list> kslist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_set_bit(Ptr<java.lang. @Unsigned Integer> stream,
      Ptr<vcap_stream_iter> itr, boolean value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_set_rule_set_actionset(Ptr<vcap_rule> rule,
      vcap_actionfield_set actionset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_set_rule_set_keyset(Ptr<vcap_rule> rule, vcap_keyfield_set keyset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void vcap_set_tc_exterr(Ptr<flow_cls_offload> fco, Ptr<vcap_rule> vrule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_show_admin_raw(Ptr<vcap_control> vctrl, Ptr<vcap_admin> admin,
      Ptr<vcap_output_print> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_arp_usage(Ptr<vcap_tc_flower_parse_usage> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_cvlan_usage(Ptr<vcap_tc_flower_parse_usage> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_ethaddr_usage(Ptr<vcap_tc_flower_parse_usage> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_ip_usage(Ptr<vcap_tc_flower_parse_usage> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_ipv4_usage(Ptr<vcap_tc_flower_parse_usage> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_ipv6_usage(Ptr<vcap_tc_flower_parse_usage> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_portnum_usage(Ptr<vcap_tc_flower_parse_usage> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_tcp_usage(Ptr<vcap_tc_flower_parse_usage> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_tc_flower_handler_vlan_usage(Ptr<vcap_tc_flower_parse_usage> st,
      vcap_key_field vid_key, vcap_key_field pcp_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_val_rule(Ptr<vcap_rule> rule, @Unsigned short l3_proto) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("vcap_verify_typegroups($arg1, $arg2, (const struct vcap_typegroup *)$arg3, $arg4, $arg5)")
  public static int vcap_verify_typegroups(Ptr<java.lang. @Unsigned Integer> stream, int sw_width,
      Ptr<vcap_typegroup> tgt, boolean mask, int sw_max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_write_counter(Ptr<vcap_rule_internal> ri, Ptr<vcap_counter> ctr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int vcap_write_rule(Ptr<vcap_rule_internal> ri) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_type"
  )
  public enum vcap_type implements Enum<vcap_type>, TypedEnum<vcap_type, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_TYPE_ES0 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_TYPE_ES0"
    )
    VCAP_TYPE_ES0,

    /**
     * {@code VCAP_TYPE_ES2 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_TYPE_ES2"
    )
    VCAP_TYPE_ES2,

    /**
     * {@code VCAP_TYPE_IS0 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_TYPE_IS0"
    )
    VCAP_TYPE_IS0,

    /**
     * {@code VCAP_TYPE_IS1 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_TYPE_IS1"
    )
    VCAP_TYPE_IS1,

    /**
     * {@code VCAP_TYPE_IS2 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_TYPE_IS2"
    )
    VCAP_TYPE_IS2,

    /**
     * {@code VCAP_TYPE_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCAP_TYPE_MAX"
    )
    VCAP_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_keyfield_set"
  )
  public enum vcap_keyfield_set implements Enum<vcap_keyfield_set>, TypedEnum<vcap_keyfield_set, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_KFS_NO_VALUE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_KFS_NO_VALUE"
    )
    VCAP_KFS_NO_VALUE,

    /**
     * {@code VCAP_KFS_5TUPLE_IP4 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_KFS_5TUPLE_IP4"
    )
    VCAP_KFS_5TUPLE_IP4,

    /**
     * {@code VCAP_KFS_5TUPLE_IP6 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_KFS_5TUPLE_IP6"
    )
    VCAP_KFS_5TUPLE_IP6,

    /**
     * {@code VCAP_KFS_7TUPLE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_KFS_7TUPLE"
    )
    VCAP_KFS_7TUPLE,

    /**
     * {@code VCAP_KFS_ARP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_KFS_ARP"
    )
    VCAP_KFS_ARP,

    /**
     * {@code VCAP_KFS_DBL_VID = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCAP_KFS_DBL_VID"
    )
    VCAP_KFS_DBL_VID,

    /**
     * {@code VCAP_KFS_DMAC_VID = 6}
     */
    @EnumMember(
        value = 6L,
        name = "VCAP_KFS_DMAC_VID"
    )
    VCAP_KFS_DMAC_VID,

    /**
     * {@code VCAP_KFS_ETAG = 7}
     */
    @EnumMember(
        value = 7L,
        name = "VCAP_KFS_ETAG"
    )
    VCAP_KFS_ETAG,

    /**
     * {@code VCAP_KFS_IP4_OTHER = 8}
     */
    @EnumMember(
        value = 8L,
        name = "VCAP_KFS_IP4_OTHER"
    )
    VCAP_KFS_IP4_OTHER,

    /**
     * {@code VCAP_KFS_IP4_TCP_UDP = 9}
     */
    @EnumMember(
        value = 9L,
        name = "VCAP_KFS_IP4_TCP_UDP"
    )
    VCAP_KFS_IP4_TCP_UDP,

    /**
     * {@code VCAP_KFS_IP4_VID = 10}
     */
    @EnumMember(
        value = 10L,
        name = "VCAP_KFS_IP4_VID"
    )
    VCAP_KFS_IP4_VID,

    /**
     * {@code VCAP_KFS_IP6_OTHER = 11}
     */
    @EnumMember(
        value = 11L,
        name = "VCAP_KFS_IP6_OTHER"
    )
    VCAP_KFS_IP6_OTHER,

    /**
     * {@code VCAP_KFS_IP6_STD = 12}
     */
    @EnumMember(
        value = 12L,
        name = "VCAP_KFS_IP6_STD"
    )
    VCAP_KFS_IP6_STD,

    /**
     * {@code VCAP_KFS_IP6_TCP_UDP = 13}
     */
    @EnumMember(
        value = 13L,
        name = "VCAP_KFS_IP6_TCP_UDP"
    )
    VCAP_KFS_IP6_TCP_UDP,

    /**
     * {@code VCAP_KFS_IP6_VID = 14}
     */
    @EnumMember(
        value = 14L,
        name = "VCAP_KFS_IP6_VID"
    )
    VCAP_KFS_IP6_VID,

    /**
     * {@code VCAP_KFS_IP_7TUPLE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "VCAP_KFS_IP_7TUPLE"
    )
    VCAP_KFS_IP_7TUPLE,

    /**
     * {@code VCAP_KFS_ISDX = 16}
     */
    @EnumMember(
        value = 16L,
        name = "VCAP_KFS_ISDX"
    )
    VCAP_KFS_ISDX,

    /**
     * {@code VCAP_KFS_LL_FULL = 17}
     */
    @EnumMember(
        value = 17L,
        name = "VCAP_KFS_LL_FULL"
    )
    VCAP_KFS_LL_FULL,

    /**
     * {@code VCAP_KFS_MAC_ETYPE = 18}
     */
    @EnumMember(
        value = 18L,
        name = "VCAP_KFS_MAC_ETYPE"
    )
    VCAP_KFS_MAC_ETYPE,

    /**
     * {@code VCAP_KFS_MAC_LLC = 19}
     */
    @EnumMember(
        value = 19L,
        name = "VCAP_KFS_MAC_LLC"
    )
    VCAP_KFS_MAC_LLC,

    /**
     * {@code VCAP_KFS_MAC_SNAP = 20}
     */
    @EnumMember(
        value = 20L,
        name = "VCAP_KFS_MAC_SNAP"
    )
    VCAP_KFS_MAC_SNAP,

    /**
     * {@code VCAP_KFS_NORMAL = 21}
     */
    @EnumMember(
        value = 21L,
        name = "VCAP_KFS_NORMAL"
    )
    VCAP_KFS_NORMAL,

    /**
     * {@code VCAP_KFS_NORMAL_5TUPLE_IP4 = 22}
     */
    @EnumMember(
        value = 22L,
        name = "VCAP_KFS_NORMAL_5TUPLE_IP4"
    )
    VCAP_KFS_NORMAL_5TUPLE_IP4,

    /**
     * {@code VCAP_KFS_NORMAL_7TUPLE = 23}
     */
    @EnumMember(
        value = 23L,
        name = "VCAP_KFS_NORMAL_7TUPLE"
    )
    VCAP_KFS_NORMAL_7TUPLE,

    /**
     * {@code VCAP_KFS_NORMAL_IP6 = 24}
     */
    @EnumMember(
        value = 24L,
        name = "VCAP_KFS_NORMAL_IP6"
    )
    VCAP_KFS_NORMAL_IP6,

    /**
     * {@code VCAP_KFS_OAM = 25}
     */
    @EnumMember(
        value = 25L,
        name = "VCAP_KFS_OAM"
    )
    VCAP_KFS_OAM,

    /**
     * {@code VCAP_KFS_PURE_5TUPLE_IP4 = 26}
     */
    @EnumMember(
        value = 26L,
        name = "VCAP_KFS_PURE_5TUPLE_IP4"
    )
    VCAP_KFS_PURE_5TUPLE_IP4,

    /**
     * {@code VCAP_KFS_RT = 27}
     */
    @EnumMember(
        value = 27L,
        name = "VCAP_KFS_RT"
    )
    VCAP_KFS_RT,

    /**
     * {@code VCAP_KFS_SMAC_SIP4 = 28}
     */
    @EnumMember(
        value = 28L,
        name = "VCAP_KFS_SMAC_SIP4"
    )
    VCAP_KFS_SMAC_SIP4,

    /**
     * {@code VCAP_KFS_SMAC_SIP6 = 29}
     */
    @EnumMember(
        value = 29L,
        name = "VCAP_KFS_SMAC_SIP6"
    )
    VCAP_KFS_SMAC_SIP6,

    /**
     * {@code VCAP_KFS_VID = 30}
     */
    @EnumMember(
        value = 30L,
        name = "VCAP_KFS_VID"
    )
    VCAP_KFS_VID
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_key_field"
  )
  public enum vcap_key_field implements Enum<vcap_key_field>, TypedEnum<vcap_key_field, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_KF_NO_VALUE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_KF_NO_VALUE"
    )
    VCAP_KF_NO_VALUE,

    /**
     * {@code VCAP_KF_8021BR_ECID_BASE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_KF_8021BR_ECID_BASE"
    )
    VCAP_KF_8021BR_ECID_BASE,

    /**
     * {@code VCAP_KF_8021BR_ECID_EXT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_KF_8021BR_ECID_EXT"
    )
    VCAP_KF_8021BR_ECID_EXT,

    /**
     * {@code VCAP_KF_8021BR_E_TAGGED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_KF_8021BR_E_TAGGED"
    )
    VCAP_KF_8021BR_E_TAGGED,

    /**
     * {@code VCAP_KF_8021BR_GRP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_KF_8021BR_GRP"
    )
    VCAP_KF_8021BR_GRP,

    /**
     * {@code VCAP_KF_8021BR_IGR_ECID_BASE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCAP_KF_8021BR_IGR_ECID_BASE"
    )
    VCAP_KF_8021BR_IGR_ECID_BASE,

    /**
     * {@code VCAP_KF_8021BR_IGR_ECID_EXT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "VCAP_KF_8021BR_IGR_ECID_EXT"
    )
    VCAP_KF_8021BR_IGR_ECID_EXT,

    /**
     * {@code VCAP_KF_8021CB_R_TAGGED_IS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "VCAP_KF_8021CB_R_TAGGED_IS"
    )
    VCAP_KF_8021CB_R_TAGGED_IS,

    /**
     * {@code VCAP_KF_8021Q_DEI0 = 8}
     */
    @EnumMember(
        value = 8L,
        name = "VCAP_KF_8021Q_DEI0"
    )
    VCAP_KF_8021Q_DEI0,

    /**
     * {@code VCAP_KF_8021Q_DEI1 = 9}
     */
    @EnumMember(
        value = 9L,
        name = "VCAP_KF_8021Q_DEI1"
    )
    VCAP_KF_8021Q_DEI1,

    /**
     * {@code VCAP_KF_8021Q_DEI2 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "VCAP_KF_8021Q_DEI2"
    )
    VCAP_KF_8021Q_DEI2,

    /**
     * {@code VCAP_KF_8021Q_DEI_CLS = 11}
     */
    @EnumMember(
        value = 11L,
        name = "VCAP_KF_8021Q_DEI_CLS"
    )
    VCAP_KF_8021Q_DEI_CLS,

    /**
     * {@code VCAP_KF_8021Q_PCP0 = 12}
     */
    @EnumMember(
        value = 12L,
        name = "VCAP_KF_8021Q_PCP0"
    )
    VCAP_KF_8021Q_PCP0,

    /**
     * {@code VCAP_KF_8021Q_PCP1 = 13}
     */
    @EnumMember(
        value = 13L,
        name = "VCAP_KF_8021Q_PCP1"
    )
    VCAP_KF_8021Q_PCP1,

    /**
     * {@code VCAP_KF_8021Q_PCP2 = 14}
     */
    @EnumMember(
        value = 14L,
        name = "VCAP_KF_8021Q_PCP2"
    )
    VCAP_KF_8021Q_PCP2,

    /**
     * {@code VCAP_KF_8021Q_PCP_CLS = 15}
     */
    @EnumMember(
        value = 15L,
        name = "VCAP_KF_8021Q_PCP_CLS"
    )
    VCAP_KF_8021Q_PCP_CLS,

    /**
     * {@code VCAP_KF_8021Q_TPID = 16}
     */
    @EnumMember(
        value = 16L,
        name = "VCAP_KF_8021Q_TPID"
    )
    VCAP_KF_8021Q_TPID,

    /**
     * {@code VCAP_KF_8021Q_TPID0 = 17}
     */
    @EnumMember(
        value = 17L,
        name = "VCAP_KF_8021Q_TPID0"
    )
    VCAP_KF_8021Q_TPID0,

    /**
     * {@code VCAP_KF_8021Q_TPID1 = 18}
     */
    @EnumMember(
        value = 18L,
        name = "VCAP_KF_8021Q_TPID1"
    )
    VCAP_KF_8021Q_TPID1,

    /**
     * {@code VCAP_KF_8021Q_TPID2 = 19}
     */
    @EnumMember(
        value = 19L,
        name = "VCAP_KF_8021Q_TPID2"
    )
    VCAP_KF_8021Q_TPID2,

    /**
     * {@code VCAP_KF_8021Q_VID0 = 20}
     */
    @EnumMember(
        value = 20L,
        name = "VCAP_KF_8021Q_VID0"
    )
    VCAP_KF_8021Q_VID0,

    /**
     * {@code VCAP_KF_8021Q_VID1 = 21}
     */
    @EnumMember(
        value = 21L,
        name = "VCAP_KF_8021Q_VID1"
    )
    VCAP_KF_8021Q_VID1,

    /**
     * {@code VCAP_KF_8021Q_VID2 = 22}
     */
    @EnumMember(
        value = 22L,
        name = "VCAP_KF_8021Q_VID2"
    )
    VCAP_KF_8021Q_VID2,

    /**
     * {@code VCAP_KF_8021Q_VID_CLS = 23}
     */
    @EnumMember(
        value = 23L,
        name = "VCAP_KF_8021Q_VID_CLS"
    )
    VCAP_KF_8021Q_VID_CLS,

    /**
     * {@code VCAP_KF_8021Q_VLAN_DBL_TAGGED_IS = 24}
     */
    @EnumMember(
        value = 24L,
        name = "VCAP_KF_8021Q_VLAN_DBL_TAGGED_IS"
    )
    VCAP_KF_8021Q_VLAN_DBL_TAGGED_IS,

    /**
     * {@code VCAP_KF_8021Q_VLAN_TAGGED_IS = 25}
     */
    @EnumMember(
        value = 25L,
        name = "VCAP_KF_8021Q_VLAN_TAGGED_IS"
    )
    VCAP_KF_8021Q_VLAN_TAGGED_IS,

    /**
     * {@code VCAP_KF_8021Q_VLAN_TAGS = 26}
     */
    @EnumMember(
        value = 26L,
        name = "VCAP_KF_8021Q_VLAN_TAGS"
    )
    VCAP_KF_8021Q_VLAN_TAGS,

    /**
     * {@code VCAP_KF_ACL_GRP_ID = 27}
     */
    @EnumMember(
        value = 27L,
        name = "VCAP_KF_ACL_GRP_ID"
    )
    VCAP_KF_ACL_GRP_ID,

    /**
     * {@code VCAP_KF_ARP_ADDR_SPACE_OK_IS = 28}
     */
    @EnumMember(
        value = 28L,
        name = "VCAP_KF_ARP_ADDR_SPACE_OK_IS"
    )
    VCAP_KF_ARP_ADDR_SPACE_OK_IS,

    /**
     * {@code VCAP_KF_ARP_LEN_OK_IS = 29}
     */
    @EnumMember(
        value = 29L,
        name = "VCAP_KF_ARP_LEN_OK_IS"
    )
    VCAP_KF_ARP_LEN_OK_IS,

    /**
     * {@code VCAP_KF_ARP_OPCODE = 30}
     */
    @EnumMember(
        value = 30L,
        name = "VCAP_KF_ARP_OPCODE"
    )
    VCAP_KF_ARP_OPCODE,

    /**
     * {@code VCAP_KF_ARP_OPCODE_UNKNOWN_IS = 31}
     */
    @EnumMember(
        value = 31L,
        name = "VCAP_KF_ARP_OPCODE_UNKNOWN_IS"
    )
    VCAP_KF_ARP_OPCODE_UNKNOWN_IS,

    /**
     * {@code VCAP_KF_ARP_PROTO_SPACE_OK_IS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "VCAP_KF_ARP_PROTO_SPACE_OK_IS"
    )
    VCAP_KF_ARP_PROTO_SPACE_OK_IS,

    /**
     * {@code VCAP_KF_ARP_SENDER_MATCH_IS = 33}
     */
    @EnumMember(
        value = 33L,
        name = "VCAP_KF_ARP_SENDER_MATCH_IS"
    )
    VCAP_KF_ARP_SENDER_MATCH_IS,

    /**
     * {@code VCAP_KF_ARP_TGT_MATCH_IS = 34}
     */
    @EnumMember(
        value = 34L,
        name = "VCAP_KF_ARP_TGT_MATCH_IS"
    )
    VCAP_KF_ARP_TGT_MATCH_IS,

    /**
     * {@code VCAP_KF_COSID_CLS = 35}
     */
    @EnumMember(
        value = 35L,
        name = "VCAP_KF_COSID_CLS"
    )
    VCAP_KF_COSID_CLS,

    /**
     * {@code VCAP_KF_ES0_ISDX_KEY_ENA = 36}
     */
    @EnumMember(
        value = 36L,
        name = "VCAP_KF_ES0_ISDX_KEY_ENA"
    )
    VCAP_KF_ES0_ISDX_KEY_ENA,

    /**
     * {@code VCAP_KF_ETYPE = 37}
     */
    @EnumMember(
        value = 37L,
        name = "VCAP_KF_ETYPE"
    )
    VCAP_KF_ETYPE,

    /**
     * {@code VCAP_KF_ETYPE_LEN_IS = 38}
     */
    @EnumMember(
        value = 38L,
        name = "VCAP_KF_ETYPE_LEN_IS"
    )
    VCAP_KF_ETYPE_LEN_IS,

    /**
     * {@code VCAP_KF_HOST_MATCH = 39}
     */
    @EnumMember(
        value = 39L,
        name = "VCAP_KF_HOST_MATCH"
    )
    VCAP_KF_HOST_MATCH,

    /**
     * {@code VCAP_KF_IF_EGR_PORT_MASK = 40}
     */
    @EnumMember(
        value = 40L,
        name = "VCAP_KF_IF_EGR_PORT_MASK"
    )
    VCAP_KF_IF_EGR_PORT_MASK,

    /**
     * {@code VCAP_KF_IF_EGR_PORT_MASK_RNG = 41}
     */
    @EnumMember(
        value = 41L,
        name = "VCAP_KF_IF_EGR_PORT_MASK_RNG"
    )
    VCAP_KF_IF_EGR_PORT_MASK_RNG,

    /**
     * {@code VCAP_KF_IF_EGR_PORT_NO = 42}
     */
    @EnumMember(
        value = 42L,
        name = "VCAP_KF_IF_EGR_PORT_NO"
    )
    VCAP_KF_IF_EGR_PORT_NO,

    /**
     * {@code VCAP_KF_IF_IGR_PORT = 43}
     */
    @EnumMember(
        value = 43L,
        name = "VCAP_KF_IF_IGR_PORT"
    )
    VCAP_KF_IF_IGR_PORT,

    /**
     * {@code VCAP_KF_IF_IGR_PORT_MASK = 44}
     */
    @EnumMember(
        value = 44L,
        name = "VCAP_KF_IF_IGR_PORT_MASK"
    )
    VCAP_KF_IF_IGR_PORT_MASK,

    /**
     * {@code VCAP_KF_IF_IGR_PORT_MASK_L3 = 45}
     */
    @EnumMember(
        value = 45L,
        name = "VCAP_KF_IF_IGR_PORT_MASK_L3"
    )
    VCAP_KF_IF_IGR_PORT_MASK_L3,

    /**
     * {@code VCAP_KF_IF_IGR_PORT_MASK_RNG = 46}
     */
    @EnumMember(
        value = 46L,
        name = "VCAP_KF_IF_IGR_PORT_MASK_RNG"
    )
    VCAP_KF_IF_IGR_PORT_MASK_RNG,

    /**
     * {@code VCAP_KF_IF_IGR_PORT_MASK_SEL = 47}
     */
    @EnumMember(
        value = 47L,
        name = "VCAP_KF_IF_IGR_PORT_MASK_SEL"
    )
    VCAP_KF_IF_IGR_PORT_MASK_SEL,

    /**
     * {@code VCAP_KF_IF_IGR_PORT_SEL = 48}
     */
    @EnumMember(
        value = 48L,
        name = "VCAP_KF_IF_IGR_PORT_SEL"
    )
    VCAP_KF_IF_IGR_PORT_SEL,

    /**
     * {@code VCAP_KF_IP4_IS = 49}
     */
    @EnumMember(
        value = 49L,
        name = "VCAP_KF_IP4_IS"
    )
    VCAP_KF_IP4_IS,

    /**
     * {@code VCAP_KF_IP_MC_IS = 50}
     */
    @EnumMember(
        value = 50L,
        name = "VCAP_KF_IP_MC_IS"
    )
    VCAP_KF_IP_MC_IS,

    /**
     * {@code VCAP_KF_IP_PAYLOAD_5TUPLE = 51}
     */
    @EnumMember(
        value = 51L,
        name = "VCAP_KF_IP_PAYLOAD_5TUPLE"
    )
    VCAP_KF_IP_PAYLOAD_5TUPLE,

    /**
     * {@code VCAP_KF_IP_PAYLOAD_S1_IP6 = 52}
     */
    @EnumMember(
        value = 52L,
        name = "VCAP_KF_IP_PAYLOAD_S1_IP6"
    )
    VCAP_KF_IP_PAYLOAD_S1_IP6,

    /**
     * {@code VCAP_KF_IP_SNAP_IS = 53}
     */
    @EnumMember(
        value = 53L,
        name = "VCAP_KF_IP_SNAP_IS"
    )
    VCAP_KF_IP_SNAP_IS,

    /**
     * {@code VCAP_KF_ISDX_CLS = 54}
     */
    @EnumMember(
        value = 54L,
        name = "VCAP_KF_ISDX_CLS"
    )
    VCAP_KF_ISDX_CLS,

    /**
     * {@code VCAP_KF_ISDX_GT0_IS = 55}
     */
    @EnumMember(
        value = 55L,
        name = "VCAP_KF_ISDX_GT0_IS"
    )
    VCAP_KF_ISDX_GT0_IS,

    /**
     * {@code VCAP_KF_L2_BC_IS = 56}
     */
    @EnumMember(
        value = 56L,
        name = "VCAP_KF_L2_BC_IS"
    )
    VCAP_KF_L2_BC_IS,

    /**
     * {@code VCAP_KF_L2_DMAC = 57}
     */
    @EnumMember(
        value = 57L,
        name = "VCAP_KF_L2_DMAC"
    )
    VCAP_KF_L2_DMAC,

    /**
     * {@code VCAP_KF_L2_FRM_TYPE = 58}
     */
    @EnumMember(
        value = 58L,
        name = "VCAP_KF_L2_FRM_TYPE"
    )
    VCAP_KF_L2_FRM_TYPE,

    /**
     * {@code VCAP_KF_L2_FWD_IS = 59}
     */
    @EnumMember(
        value = 59L,
        name = "VCAP_KF_L2_FWD_IS"
    )
    VCAP_KF_L2_FWD_IS,

    /**
     * {@code VCAP_KF_L2_LLC = 60}
     */
    @EnumMember(
        value = 60L,
        name = "VCAP_KF_L2_LLC"
    )
    VCAP_KF_L2_LLC,

    /**
     * {@code VCAP_KF_L2_MAC = 61}
     */
    @EnumMember(
        value = 61L,
        name = "VCAP_KF_L2_MAC"
    )
    VCAP_KF_L2_MAC,

    /**
     * {@code VCAP_KF_L2_MC_IS = 62}
     */
    @EnumMember(
        value = 62L,
        name = "VCAP_KF_L2_MC_IS"
    )
    VCAP_KF_L2_MC_IS,

    /**
     * {@code VCAP_KF_L2_PAYLOAD0 = 63}
     */
    @EnumMember(
        value = 63L,
        name = "VCAP_KF_L2_PAYLOAD0"
    )
    VCAP_KF_L2_PAYLOAD0,

    /**
     * {@code VCAP_KF_L2_PAYLOAD1 = 64}
     */
    @EnumMember(
        value = 64L,
        name = "VCAP_KF_L2_PAYLOAD1"
    )
    VCAP_KF_L2_PAYLOAD1,

    /**
     * {@code VCAP_KF_L2_PAYLOAD2 = 65}
     */
    @EnumMember(
        value = 65L,
        name = "VCAP_KF_L2_PAYLOAD2"
    )
    VCAP_KF_L2_PAYLOAD2,

    /**
     * {@code VCAP_KF_L2_PAYLOAD_ETYPE = 66}
     */
    @EnumMember(
        value = 66L,
        name = "VCAP_KF_L2_PAYLOAD_ETYPE"
    )
    VCAP_KF_L2_PAYLOAD_ETYPE,

    /**
     * {@code VCAP_KF_L2_SMAC = 67}
     */
    @EnumMember(
        value = 67L,
        name = "VCAP_KF_L2_SMAC"
    )
    VCAP_KF_L2_SMAC,

    /**
     * {@code VCAP_KF_L2_SNAP = 68}
     */
    @EnumMember(
        value = 68L,
        name = "VCAP_KF_L2_SNAP"
    )
    VCAP_KF_L2_SNAP,

    /**
     * {@code VCAP_KF_L3_DIP_EQ_SIP_IS = 69}
     */
    @EnumMember(
        value = 69L,
        name = "VCAP_KF_L3_DIP_EQ_SIP_IS"
    )
    VCAP_KF_L3_DIP_EQ_SIP_IS,

    /**
     * {@code VCAP_KF_L3_DPL_CLS = 70}
     */
    @EnumMember(
        value = 70L,
        name = "VCAP_KF_L3_DPL_CLS"
    )
    VCAP_KF_L3_DPL_CLS,

    /**
     * {@code VCAP_KF_L3_DSCP = 71}
     */
    @EnumMember(
        value = 71L,
        name = "VCAP_KF_L3_DSCP"
    )
    VCAP_KF_L3_DSCP,

    /**
     * {@code VCAP_KF_L3_DST_IS = 72}
     */
    @EnumMember(
        value = 72L,
        name = "VCAP_KF_L3_DST_IS"
    )
    VCAP_KF_L3_DST_IS,

    /**
     * {@code VCAP_KF_L3_FRAGMENT = 73}
     */
    @EnumMember(
        value = 73L,
        name = "VCAP_KF_L3_FRAGMENT"
    )
    VCAP_KF_L3_FRAGMENT,

    /**
     * {@code VCAP_KF_L3_FRAGMENT_TYPE = 74}
     */
    @EnumMember(
        value = 74L,
        name = "VCAP_KF_L3_FRAGMENT_TYPE"
    )
    VCAP_KF_L3_FRAGMENT_TYPE,

    /**
     * {@code VCAP_KF_L3_FRAG_INVLD_L4_LEN = 75}
     */
    @EnumMember(
        value = 75L,
        name = "VCAP_KF_L3_FRAG_INVLD_L4_LEN"
    )
    VCAP_KF_L3_FRAG_INVLD_L4_LEN,

    /**
     * {@code VCAP_KF_L3_FRAG_OFS_GT0 = 76}
     */
    @EnumMember(
        value = 76L,
        name = "VCAP_KF_L3_FRAG_OFS_GT0"
    )
    VCAP_KF_L3_FRAG_OFS_GT0,

    /**
     * {@code VCAP_KF_L3_IP4_DIP = 77}
     */
    @EnumMember(
        value = 77L,
        name = "VCAP_KF_L3_IP4_DIP"
    )
    VCAP_KF_L3_IP4_DIP,

    /**
     * {@code VCAP_KF_L3_IP4_SIP = 78}
     */
    @EnumMember(
        value = 78L,
        name = "VCAP_KF_L3_IP4_SIP"
    )
    VCAP_KF_L3_IP4_SIP,

    /**
     * {@code VCAP_KF_L3_IP6_DIP = 79}
     */
    @EnumMember(
        value = 79L,
        name = "VCAP_KF_L3_IP6_DIP"
    )
    VCAP_KF_L3_IP6_DIP,

    /**
     * {@code VCAP_KF_L3_IP6_DIP_MSB = 80}
     */
    @EnumMember(
        value = 80L,
        name = "VCAP_KF_L3_IP6_DIP_MSB"
    )
    VCAP_KF_L3_IP6_DIP_MSB,

    /**
     * {@code VCAP_KF_L3_IP6_SIP = 81}
     */
    @EnumMember(
        value = 81L,
        name = "VCAP_KF_L3_IP6_SIP"
    )
    VCAP_KF_L3_IP6_SIP,

    /**
     * {@code VCAP_KF_L3_IP6_SIP_MSB = 82}
     */
    @EnumMember(
        value = 82L,
        name = "VCAP_KF_L3_IP6_SIP_MSB"
    )
    VCAP_KF_L3_IP6_SIP_MSB,

    /**
     * {@code VCAP_KF_L3_IP_PROTO = 83}
     */
    @EnumMember(
        value = 83L,
        name = "VCAP_KF_L3_IP_PROTO"
    )
    VCAP_KF_L3_IP_PROTO,

    /**
     * {@code VCAP_KF_L3_OPTIONS_IS = 84}
     */
    @EnumMember(
        value = 84L,
        name = "VCAP_KF_L3_OPTIONS_IS"
    )
    VCAP_KF_L3_OPTIONS_IS,

    /**
     * {@code VCAP_KF_L3_PAYLOAD = 85}
     */
    @EnumMember(
        value = 85L,
        name = "VCAP_KF_L3_PAYLOAD"
    )
    VCAP_KF_L3_PAYLOAD,

    /**
     * {@code VCAP_KF_L3_RT_IS = 86}
     */
    @EnumMember(
        value = 86L,
        name = "VCAP_KF_L3_RT_IS"
    )
    VCAP_KF_L3_RT_IS,

    /**
     * {@code VCAP_KF_L3_TOS = 87}
     */
    @EnumMember(
        value = 87L,
        name = "VCAP_KF_L3_TOS"
    )
    VCAP_KF_L3_TOS,

    /**
     * {@code VCAP_KF_L3_TTL_GT0 = 88}
     */
    @EnumMember(
        value = 88L,
        name = "VCAP_KF_L3_TTL_GT0"
    )
    VCAP_KF_L3_TTL_GT0,

    /**
     * {@code VCAP_KF_L4_1588_DOM = 89}
     */
    @EnumMember(
        value = 89L,
        name = "VCAP_KF_L4_1588_DOM"
    )
    VCAP_KF_L4_1588_DOM,

    /**
     * {@code VCAP_KF_L4_1588_VER = 90}
     */
    @EnumMember(
        value = 90L,
        name = "VCAP_KF_L4_1588_VER"
    )
    VCAP_KF_L4_1588_VER,

    /**
     * {@code VCAP_KF_L4_ACK = 91}
     */
    @EnumMember(
        value = 91L,
        name = "VCAP_KF_L4_ACK"
    )
    VCAP_KF_L4_ACK,

    /**
     * {@code VCAP_KF_L4_DPORT = 92}
     */
    @EnumMember(
        value = 92L,
        name = "VCAP_KF_L4_DPORT"
    )
    VCAP_KF_L4_DPORT,

    /**
     * {@code VCAP_KF_L4_FIN = 93}
     */
    @EnumMember(
        value = 93L,
        name = "VCAP_KF_L4_FIN"
    )
    VCAP_KF_L4_FIN,

    /**
     * {@code VCAP_KF_L4_PAYLOAD = 94}
     */
    @EnumMember(
        value = 94L,
        name = "VCAP_KF_L4_PAYLOAD"
    )
    VCAP_KF_L4_PAYLOAD,

    /**
     * {@code VCAP_KF_L4_PSH = 95}
     */
    @EnumMember(
        value = 95L,
        name = "VCAP_KF_L4_PSH"
    )
    VCAP_KF_L4_PSH,

    /**
     * {@code VCAP_KF_L4_RNG = 96}
     */
    @EnumMember(
        value = 96L,
        name = "VCAP_KF_L4_RNG"
    )
    VCAP_KF_L4_RNG,

    /**
     * {@code VCAP_KF_L4_RST = 97}
     */
    @EnumMember(
        value = 97L,
        name = "VCAP_KF_L4_RST"
    )
    VCAP_KF_L4_RST,

    /**
     * {@code VCAP_KF_L4_SEQUENCE_EQ0_IS = 98}
     */
    @EnumMember(
        value = 98L,
        name = "VCAP_KF_L4_SEQUENCE_EQ0_IS"
    )
    VCAP_KF_L4_SEQUENCE_EQ0_IS,

    /**
     * {@code VCAP_KF_L4_SPORT = 99}
     */
    @EnumMember(
        value = 99L,
        name = "VCAP_KF_L4_SPORT"
    )
    VCAP_KF_L4_SPORT,

    /**
     * {@code VCAP_KF_L4_SPORT_EQ_DPORT_IS = 100}
     */
    @EnumMember(
        value = 100L,
        name = "VCAP_KF_L4_SPORT_EQ_DPORT_IS"
    )
    VCAP_KF_L4_SPORT_EQ_DPORT_IS,

    /**
     * {@code VCAP_KF_L4_SYN = 101}
     */
    @EnumMember(
        value = 101L,
        name = "VCAP_KF_L4_SYN"
    )
    VCAP_KF_L4_SYN,

    /**
     * {@code VCAP_KF_L4_URG = 102}
     */
    @EnumMember(
        value = 102L,
        name = "VCAP_KF_L4_URG"
    )
    VCAP_KF_L4_URG,

    /**
     * {@code VCAP_KF_LOOKUP_FIRST_IS = 103}
     */
    @EnumMember(
        value = 103L,
        name = "VCAP_KF_LOOKUP_FIRST_IS"
    )
    VCAP_KF_LOOKUP_FIRST_IS,

    /**
     * {@code VCAP_KF_LOOKUP_GEN_IDX = 104}
     */
    @EnumMember(
        value = 104L,
        name = "VCAP_KF_LOOKUP_GEN_IDX"
    )
    VCAP_KF_LOOKUP_GEN_IDX,

    /**
     * {@code VCAP_KF_LOOKUP_GEN_IDX_SEL = 105}
     */
    @EnumMember(
        value = 105L,
        name = "VCAP_KF_LOOKUP_GEN_IDX_SEL"
    )
    VCAP_KF_LOOKUP_GEN_IDX_SEL,

    /**
     * {@code VCAP_KF_LOOKUP_INDEX = 106}
     */
    @EnumMember(
        value = 106L,
        name = "VCAP_KF_LOOKUP_INDEX"
    )
    VCAP_KF_LOOKUP_INDEX,

    /**
     * {@code VCAP_KF_LOOKUP_PAG = 107}
     */
    @EnumMember(
        value = 107L,
        name = "VCAP_KF_LOOKUP_PAG"
    )
    VCAP_KF_LOOKUP_PAG,

    /**
     * {@code VCAP_KF_MIRROR_PROBE = 108}
     */
    @EnumMember(
        value = 108L,
        name = "VCAP_KF_MIRROR_PROBE"
    )
    VCAP_KF_MIRROR_PROBE,

    /**
     * {@code VCAP_KF_OAM_CCM_CNTS_EQ0 = 109}
     */
    @EnumMember(
        value = 109L,
        name = "VCAP_KF_OAM_CCM_CNTS_EQ0"
    )
    VCAP_KF_OAM_CCM_CNTS_EQ0,

    /**
     * {@code VCAP_KF_OAM_DETECTED = 110}
     */
    @EnumMember(
        value = 110L,
        name = "VCAP_KF_OAM_DETECTED"
    )
    VCAP_KF_OAM_DETECTED,

    /**
     * {@code VCAP_KF_OAM_FLAGS = 111}
     */
    @EnumMember(
        value = 111L,
        name = "VCAP_KF_OAM_FLAGS"
    )
    VCAP_KF_OAM_FLAGS,

    /**
     * {@code VCAP_KF_OAM_MEL_FLAGS = 112}
     */
    @EnumMember(
        value = 112L,
        name = "VCAP_KF_OAM_MEL_FLAGS"
    )
    VCAP_KF_OAM_MEL_FLAGS,

    /**
     * {@code VCAP_KF_OAM_MEPID = 113}
     */
    @EnumMember(
        value = 113L,
        name = "VCAP_KF_OAM_MEPID"
    )
    VCAP_KF_OAM_MEPID,

    /**
     * {@code VCAP_KF_OAM_OPCODE = 114}
     */
    @EnumMember(
        value = 114L,
        name = "VCAP_KF_OAM_OPCODE"
    )
    VCAP_KF_OAM_OPCODE,

    /**
     * {@code VCAP_KF_OAM_VER = 115}
     */
    @EnumMember(
        value = 115L,
        name = "VCAP_KF_OAM_VER"
    )
    VCAP_KF_OAM_VER,

    /**
     * {@code VCAP_KF_OAM_Y1731_IS = 116}
     */
    @EnumMember(
        value = 116L,
        name = "VCAP_KF_OAM_Y1731_IS"
    )
    VCAP_KF_OAM_Y1731_IS,

    /**
     * {@code VCAP_KF_PDU_TYPE = 117}
     */
    @EnumMember(
        value = 117L,
        name = "VCAP_KF_PDU_TYPE"
    )
    VCAP_KF_PDU_TYPE,

    /**
     * {@code VCAP_KF_PROT_ACTIVE = 118}
     */
    @EnumMember(
        value = 118L,
        name = "VCAP_KF_PROT_ACTIVE"
    )
    VCAP_KF_PROT_ACTIVE,

    /**
     * {@code VCAP_KF_RTP_ID = 119}
     */
    @EnumMember(
        value = 119L,
        name = "VCAP_KF_RTP_ID"
    )
    VCAP_KF_RTP_ID,

    /**
     * {@code VCAP_KF_RT_FRMID = 120}
     */
    @EnumMember(
        value = 120L,
        name = "VCAP_KF_RT_FRMID"
    )
    VCAP_KF_RT_FRMID,

    /**
     * {@code VCAP_KF_RT_TYPE = 121}
     */
    @EnumMember(
        value = 121L,
        name = "VCAP_KF_RT_TYPE"
    )
    VCAP_KF_RT_TYPE,

    /**
     * {@code VCAP_KF_RT_VLAN_IDX = 122}
     */
    @EnumMember(
        value = 122L,
        name = "VCAP_KF_RT_VLAN_IDX"
    )
    VCAP_KF_RT_VLAN_IDX,

    /**
     * {@code VCAP_KF_TCP_IS = 123}
     */
    @EnumMember(
        value = 123L,
        name = "VCAP_KF_TCP_IS"
    )
    VCAP_KF_TCP_IS,

    /**
     * {@code VCAP_KF_TCP_UDP_IS = 124}
     */
    @EnumMember(
        value = 124L,
        name = "VCAP_KF_TCP_UDP_IS"
    )
    VCAP_KF_TCP_UDP_IS,

    /**
     * {@code VCAP_KF_TYPE = 125}
     */
    @EnumMember(
        value = 125L,
        name = "VCAP_KF_TYPE"
    )
    VCAP_KF_TYPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_actionfield_set"
  )
  public enum vcap_actionfield_set implements Enum<vcap_actionfield_set>, TypedEnum<vcap_actionfield_set, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_AFS_NO_VALUE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_AFS_NO_VALUE"
    )
    VCAP_AFS_NO_VALUE,

    /**
     * {@code VCAP_AFS_BASE_TYPE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_AFS_BASE_TYPE"
    )
    VCAP_AFS_BASE_TYPE,

    /**
     * {@code VCAP_AFS_CLASSIFICATION = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_AFS_CLASSIFICATION"
    )
    VCAP_AFS_CLASSIFICATION,

    /**
     * {@code VCAP_AFS_CLASS_REDUCED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_AFS_CLASS_REDUCED"
    )
    VCAP_AFS_CLASS_REDUCED,

    /**
     * {@code VCAP_AFS_ES0 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_AFS_ES0"
    )
    VCAP_AFS_ES0,

    /**
     * {@code VCAP_AFS_FULL = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCAP_AFS_FULL"
    )
    VCAP_AFS_FULL,

    /**
     * {@code VCAP_AFS_S1 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "VCAP_AFS_S1"
    )
    VCAP_AFS_S1,

    /**
     * {@code VCAP_AFS_SMAC_SIP = 7}
     */
    @EnumMember(
        value = 7L,
        name = "VCAP_AFS_SMAC_SIP"
    )
    VCAP_AFS_SMAC_SIP,

    /**
     * {@code VCAP_AFS_VID = 8}
     */
    @EnumMember(
        value = 8L,
        name = "VCAP_AFS_VID"
    )
    VCAP_AFS_VID
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_action_field"
  )
  public enum vcap_action_field implements Enum<vcap_action_field>, TypedEnum<vcap_action_field, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_AF_NO_VALUE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_AF_NO_VALUE"
    )
    VCAP_AF_NO_VALUE,

    /**
     * {@code VCAP_AF_ACL_ID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_AF_ACL_ID"
    )
    VCAP_AF_ACL_ID,

    /**
     * {@code VCAP_AF_CLS_VID_SEL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_AF_CLS_VID_SEL"
    )
    VCAP_AF_CLS_VID_SEL,

    /**
     * {@code VCAP_AF_CNT_ID = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_AF_CNT_ID"
    )
    VCAP_AF_CNT_ID,

    /**
     * {@code VCAP_AF_COPY_PORT_NUM = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_AF_COPY_PORT_NUM"
    )
    VCAP_AF_COPY_PORT_NUM,

    /**
     * {@code VCAP_AF_COPY_QUEUE_NUM = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCAP_AF_COPY_QUEUE_NUM"
    )
    VCAP_AF_COPY_QUEUE_NUM,

    /**
     * {@code VCAP_AF_CPU_COPY_ENA = 6}
     */
    @EnumMember(
        value = 6L,
        name = "VCAP_AF_CPU_COPY_ENA"
    )
    VCAP_AF_CPU_COPY_ENA,

    /**
     * {@code VCAP_AF_CPU_QU = 7}
     */
    @EnumMember(
        value = 7L,
        name = "VCAP_AF_CPU_QU"
    )
    VCAP_AF_CPU_QU,

    /**
     * {@code VCAP_AF_CPU_QUEUE_NUM = 8}
     */
    @EnumMember(
        value = 8L,
        name = "VCAP_AF_CPU_QUEUE_NUM"
    )
    VCAP_AF_CPU_QUEUE_NUM,

    /**
     * {@code VCAP_AF_CUSTOM_ACE_TYPE_ENA = 9}
     */
    @EnumMember(
        value = 9L,
        name = "VCAP_AF_CUSTOM_ACE_TYPE_ENA"
    )
    VCAP_AF_CUSTOM_ACE_TYPE_ENA,

    /**
     * {@code VCAP_AF_DEI_A_VAL = 10}
     */
    @EnumMember(
        value = 10L,
        name = "VCAP_AF_DEI_A_VAL"
    )
    VCAP_AF_DEI_A_VAL,

    /**
     * {@code VCAP_AF_DEI_B_VAL = 11}
     */
    @EnumMember(
        value = 11L,
        name = "VCAP_AF_DEI_B_VAL"
    )
    VCAP_AF_DEI_B_VAL,

    /**
     * {@code VCAP_AF_DEI_C_VAL = 12}
     */
    @EnumMember(
        value = 12L,
        name = "VCAP_AF_DEI_C_VAL"
    )
    VCAP_AF_DEI_C_VAL,

    /**
     * {@code VCAP_AF_DEI_ENA = 13}
     */
    @EnumMember(
        value = 13L,
        name = "VCAP_AF_DEI_ENA"
    )
    VCAP_AF_DEI_ENA,

    /**
     * {@code VCAP_AF_DEI_VAL = 14}
     */
    @EnumMember(
        value = 14L,
        name = "VCAP_AF_DEI_VAL"
    )
    VCAP_AF_DEI_VAL,

    /**
     * {@code VCAP_AF_DLR_SEL = 15}
     */
    @EnumMember(
        value = 15L,
        name = "VCAP_AF_DLR_SEL"
    )
    VCAP_AF_DLR_SEL,

    /**
     * {@code VCAP_AF_DP_ENA = 16}
     */
    @EnumMember(
        value = 16L,
        name = "VCAP_AF_DP_ENA"
    )
    VCAP_AF_DP_ENA,

    /**
     * {@code VCAP_AF_DP_VAL = 17}
     */
    @EnumMember(
        value = 17L,
        name = "VCAP_AF_DP_VAL"
    )
    VCAP_AF_DP_VAL,

    /**
     * {@code VCAP_AF_DSCP_ENA = 18}
     */
    @EnumMember(
        value = 18L,
        name = "VCAP_AF_DSCP_ENA"
    )
    VCAP_AF_DSCP_ENA,

    /**
     * {@code VCAP_AF_DSCP_SEL = 19}
     */
    @EnumMember(
        value = 19L,
        name = "VCAP_AF_DSCP_SEL"
    )
    VCAP_AF_DSCP_SEL,

    /**
     * {@code VCAP_AF_DSCP_VAL = 20}
     */
    @EnumMember(
        value = 20L,
        name = "VCAP_AF_DSCP_VAL"
    )
    VCAP_AF_DSCP_VAL,

    /**
     * {@code VCAP_AF_ES2_REW_CMD = 21}
     */
    @EnumMember(
        value = 21L,
        name = "VCAP_AF_ES2_REW_CMD"
    )
    VCAP_AF_ES2_REW_CMD,

    /**
     * {@code VCAP_AF_ESDX = 22}
     */
    @EnumMember(
        value = 22L,
        name = "VCAP_AF_ESDX"
    )
    VCAP_AF_ESDX,

    /**
     * {@code VCAP_AF_FWD_KILL_ENA = 23}
     */
    @EnumMember(
        value = 23L,
        name = "VCAP_AF_FWD_KILL_ENA"
    )
    VCAP_AF_FWD_KILL_ENA,

    /**
     * {@code VCAP_AF_FWD_MODE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "VCAP_AF_FWD_MODE"
    )
    VCAP_AF_FWD_MODE,

    /**
     * {@code VCAP_AF_FWD_SEL = 25}
     */
    @EnumMember(
        value = 25L,
        name = "VCAP_AF_FWD_SEL"
    )
    VCAP_AF_FWD_SEL,

    /**
     * {@code VCAP_AF_HIT_ME_ONCE = 26}
     */
    @EnumMember(
        value = 26L,
        name = "VCAP_AF_HIT_ME_ONCE"
    )
    VCAP_AF_HIT_ME_ONCE,

    /**
     * {@code VCAP_AF_HOST_MATCH = 27}
     */
    @EnumMember(
        value = 27L,
        name = "VCAP_AF_HOST_MATCH"
    )
    VCAP_AF_HOST_MATCH,

    /**
     * {@code VCAP_AF_IGNORE_PIPELINE_CTRL = 28}
     */
    @EnumMember(
        value = 28L,
        name = "VCAP_AF_IGNORE_PIPELINE_CTRL"
    )
    VCAP_AF_IGNORE_PIPELINE_CTRL,

    /**
     * {@code VCAP_AF_INTR_ENA = 29}
     */
    @EnumMember(
        value = 29L,
        name = "VCAP_AF_INTR_ENA"
    )
    VCAP_AF_INTR_ENA,

    /**
     * {@code VCAP_AF_ISDX_ADD_REPLACE_SEL = 30}
     */
    @EnumMember(
        value = 30L,
        name = "VCAP_AF_ISDX_ADD_REPLACE_SEL"
    )
    VCAP_AF_ISDX_ADD_REPLACE_SEL,

    /**
     * {@code VCAP_AF_ISDX_ADD_VAL = 31}
     */
    @EnumMember(
        value = 31L,
        name = "VCAP_AF_ISDX_ADD_VAL"
    )
    VCAP_AF_ISDX_ADD_VAL,

    /**
     * {@code VCAP_AF_ISDX_ENA = 32}
     */
    @EnumMember(
        value = 32L,
        name = "VCAP_AF_ISDX_ENA"
    )
    VCAP_AF_ISDX_ENA,

    /**
     * {@code VCAP_AF_ISDX_REPLACE_ENA = 33}
     */
    @EnumMember(
        value = 33L,
        name = "VCAP_AF_ISDX_REPLACE_ENA"
    )
    VCAP_AF_ISDX_REPLACE_ENA,

    /**
     * {@code VCAP_AF_ISDX_VAL = 34}
     */
    @EnumMember(
        value = 34L,
        name = "VCAP_AF_ISDX_VAL"
    )
    VCAP_AF_ISDX_VAL,

    /**
     * {@code VCAP_AF_LOOP_ENA = 35}
     */
    @EnumMember(
        value = 35L,
        name = "VCAP_AF_LOOP_ENA"
    )
    VCAP_AF_LOOP_ENA,

    /**
     * {@code VCAP_AF_LRN_DIS = 36}
     */
    @EnumMember(
        value = 36L,
        name = "VCAP_AF_LRN_DIS"
    )
    VCAP_AF_LRN_DIS,

    /**
     * {@code VCAP_AF_MAP_IDX = 37}
     */
    @EnumMember(
        value = 37L,
        name = "VCAP_AF_MAP_IDX"
    )
    VCAP_AF_MAP_IDX,

    /**
     * {@code VCAP_AF_MAP_KEY = 38}
     */
    @EnumMember(
        value = 38L,
        name = "VCAP_AF_MAP_KEY"
    )
    VCAP_AF_MAP_KEY,

    /**
     * {@code VCAP_AF_MAP_LOOKUP_SEL = 39}
     */
    @EnumMember(
        value = 39L,
        name = "VCAP_AF_MAP_LOOKUP_SEL"
    )
    VCAP_AF_MAP_LOOKUP_SEL,

    /**
     * {@code VCAP_AF_MASK_MODE = 40}
     */
    @EnumMember(
        value = 40L,
        name = "VCAP_AF_MASK_MODE"
    )
    VCAP_AF_MASK_MODE,

    /**
     * {@code VCAP_AF_MATCH_ID = 41}
     */
    @EnumMember(
        value = 41L,
        name = "VCAP_AF_MATCH_ID"
    )
    VCAP_AF_MATCH_ID,

    /**
     * {@code VCAP_AF_MATCH_ID_MASK = 42}
     */
    @EnumMember(
        value = 42L,
        name = "VCAP_AF_MATCH_ID_MASK"
    )
    VCAP_AF_MATCH_ID_MASK,

    /**
     * {@code VCAP_AF_MIRROR_ENA = 43}
     */
    @EnumMember(
        value = 43L,
        name = "VCAP_AF_MIRROR_ENA"
    )
    VCAP_AF_MIRROR_ENA,

    /**
     * {@code VCAP_AF_MIRROR_PROBE = 44}
     */
    @EnumMember(
        value = 44L,
        name = "VCAP_AF_MIRROR_PROBE"
    )
    VCAP_AF_MIRROR_PROBE,

    /**
     * {@code VCAP_AF_MIRROR_PROBE_ID = 45}
     */
    @EnumMember(
        value = 45L,
        name = "VCAP_AF_MIRROR_PROBE_ID"
    )
    VCAP_AF_MIRROR_PROBE_ID,

    /**
     * {@code VCAP_AF_MRP_SEL = 46}
     */
    @EnumMember(
        value = 46L,
        name = "VCAP_AF_MRP_SEL"
    )
    VCAP_AF_MRP_SEL,

    /**
     * {@code VCAP_AF_NXT_IDX = 47}
     */
    @EnumMember(
        value = 47L,
        name = "VCAP_AF_NXT_IDX"
    )
    VCAP_AF_NXT_IDX,

    /**
     * {@code VCAP_AF_NXT_IDX_CTRL = 48}
     */
    @EnumMember(
        value = 48L,
        name = "VCAP_AF_NXT_IDX_CTRL"
    )
    VCAP_AF_NXT_IDX_CTRL,

    /**
     * {@code VCAP_AF_OAM_SEL = 49}
     */
    @EnumMember(
        value = 49L,
        name = "VCAP_AF_OAM_SEL"
    )
    VCAP_AF_OAM_SEL,

    /**
     * {@code VCAP_AF_PAG_OVERRIDE_MASK = 50}
     */
    @EnumMember(
        value = 50L,
        name = "VCAP_AF_PAG_OVERRIDE_MASK"
    )
    VCAP_AF_PAG_OVERRIDE_MASK,

    /**
     * {@code VCAP_AF_PAG_VAL = 51}
     */
    @EnumMember(
        value = 51L,
        name = "VCAP_AF_PAG_VAL"
    )
    VCAP_AF_PAG_VAL,

    /**
     * {@code VCAP_AF_PCP_A_VAL = 52}
     */
    @EnumMember(
        value = 52L,
        name = "VCAP_AF_PCP_A_VAL"
    )
    VCAP_AF_PCP_A_VAL,

    /**
     * {@code VCAP_AF_PCP_B_VAL = 53}
     */
    @EnumMember(
        value = 53L,
        name = "VCAP_AF_PCP_B_VAL"
    )
    VCAP_AF_PCP_B_VAL,

    /**
     * {@code VCAP_AF_PCP_C_VAL = 54}
     */
    @EnumMember(
        value = 54L,
        name = "VCAP_AF_PCP_C_VAL"
    )
    VCAP_AF_PCP_C_VAL,

    /**
     * {@code VCAP_AF_PCP_ENA = 55}
     */
    @EnumMember(
        value = 55L,
        name = "VCAP_AF_PCP_ENA"
    )
    VCAP_AF_PCP_ENA,

    /**
     * {@code VCAP_AF_PCP_VAL = 56}
     */
    @EnumMember(
        value = 56L,
        name = "VCAP_AF_PCP_VAL"
    )
    VCAP_AF_PCP_VAL,

    /**
     * {@code VCAP_AF_PIPELINE_ACT = 57}
     */
    @EnumMember(
        value = 57L,
        name = "VCAP_AF_PIPELINE_ACT"
    )
    VCAP_AF_PIPELINE_ACT,

    /**
     * {@code VCAP_AF_PIPELINE_FORCE_ENA = 58}
     */
    @EnumMember(
        value = 58L,
        name = "VCAP_AF_PIPELINE_FORCE_ENA"
    )
    VCAP_AF_PIPELINE_FORCE_ENA,

    /**
     * {@code VCAP_AF_PIPELINE_PT = 59}
     */
    @EnumMember(
        value = 59L,
        name = "VCAP_AF_PIPELINE_PT"
    )
    VCAP_AF_PIPELINE_PT,

    /**
     * {@code VCAP_AF_POLICE_ENA = 60}
     */
    @EnumMember(
        value = 60L,
        name = "VCAP_AF_POLICE_ENA"
    )
    VCAP_AF_POLICE_ENA,

    /**
     * {@code VCAP_AF_POLICE_IDX = 61}
     */
    @EnumMember(
        value = 61L,
        name = "VCAP_AF_POLICE_IDX"
    )
    VCAP_AF_POLICE_IDX,

    /**
     * {@code VCAP_AF_POLICE_REMARK = 62}
     */
    @EnumMember(
        value = 62L,
        name = "VCAP_AF_POLICE_REMARK"
    )
    VCAP_AF_POLICE_REMARK,

    /**
     * {@code VCAP_AF_POLICE_VCAP_ONLY = 63}
     */
    @EnumMember(
        value = 63L,
        name = "VCAP_AF_POLICE_VCAP_ONLY"
    )
    VCAP_AF_POLICE_VCAP_ONLY,

    /**
     * {@code VCAP_AF_POP_VAL = 64}
     */
    @EnumMember(
        value = 64L,
        name = "VCAP_AF_POP_VAL"
    )
    VCAP_AF_POP_VAL,

    /**
     * {@code VCAP_AF_PORT_MASK = 65}
     */
    @EnumMember(
        value = 65L,
        name = "VCAP_AF_PORT_MASK"
    )
    VCAP_AF_PORT_MASK,

    /**
     * {@code VCAP_AF_PUSH_CUSTOMER_TAG = 66}
     */
    @EnumMember(
        value = 66L,
        name = "VCAP_AF_PUSH_CUSTOMER_TAG"
    )
    VCAP_AF_PUSH_CUSTOMER_TAG,

    /**
     * {@code VCAP_AF_PUSH_INNER_TAG = 67}
     */
    @EnumMember(
        value = 67L,
        name = "VCAP_AF_PUSH_INNER_TAG"
    )
    VCAP_AF_PUSH_INNER_TAG,

    /**
     * {@code VCAP_AF_PUSH_OUTER_TAG = 68}
     */
    @EnumMember(
        value = 68L,
        name = "VCAP_AF_PUSH_OUTER_TAG"
    )
    VCAP_AF_PUSH_OUTER_TAG,

    /**
     * {@code VCAP_AF_QOS_ENA = 69}
     */
    @EnumMember(
        value = 69L,
        name = "VCAP_AF_QOS_ENA"
    )
    VCAP_AF_QOS_ENA,

    /**
     * {@code VCAP_AF_QOS_VAL = 70}
     */
    @EnumMember(
        value = 70L,
        name = "VCAP_AF_QOS_VAL"
    )
    VCAP_AF_QOS_VAL,

    /**
     * {@code VCAP_AF_REW_OP = 71}
     */
    @EnumMember(
        value = 71L,
        name = "VCAP_AF_REW_OP"
    )
    VCAP_AF_REW_OP,

    /**
     * {@code VCAP_AF_RT_DIS = 72}
     */
    @EnumMember(
        value = 72L,
        name = "VCAP_AF_RT_DIS"
    )
    VCAP_AF_RT_DIS,

    /**
     * {@code VCAP_AF_SFID_ENA = 73}
     */
    @EnumMember(
        value = 73L,
        name = "VCAP_AF_SFID_ENA"
    )
    VCAP_AF_SFID_ENA,

    /**
     * {@code VCAP_AF_SFID_VAL = 74}
     */
    @EnumMember(
        value = 74L,
        name = "VCAP_AF_SFID_VAL"
    )
    VCAP_AF_SFID_VAL,

    /**
     * {@code VCAP_AF_SGID_ENA = 75}
     */
    @EnumMember(
        value = 75L,
        name = "VCAP_AF_SGID_ENA"
    )
    VCAP_AF_SGID_ENA,

    /**
     * {@code VCAP_AF_SGID_VAL = 76}
     */
    @EnumMember(
        value = 76L,
        name = "VCAP_AF_SGID_VAL"
    )
    VCAP_AF_SGID_VAL,

    /**
     * {@code VCAP_AF_SWAP_MACS_ENA = 77}
     */
    @EnumMember(
        value = 77L,
        name = "VCAP_AF_SWAP_MACS_ENA"
    )
    VCAP_AF_SWAP_MACS_ENA,

    /**
     * {@code VCAP_AF_TAG_A_DEI_SEL = 78}
     */
    @EnumMember(
        value = 78L,
        name = "VCAP_AF_TAG_A_DEI_SEL"
    )
    VCAP_AF_TAG_A_DEI_SEL,

    /**
     * {@code VCAP_AF_TAG_A_PCP_SEL = 79}
     */
    @EnumMember(
        value = 79L,
        name = "VCAP_AF_TAG_A_PCP_SEL"
    )
    VCAP_AF_TAG_A_PCP_SEL,

    /**
     * {@code VCAP_AF_TAG_A_TPID_SEL = 80}
     */
    @EnumMember(
        value = 80L,
        name = "VCAP_AF_TAG_A_TPID_SEL"
    )
    VCAP_AF_TAG_A_TPID_SEL,

    /**
     * {@code VCAP_AF_TAG_A_VID_SEL = 81}
     */
    @EnumMember(
        value = 81L,
        name = "VCAP_AF_TAG_A_VID_SEL"
    )
    VCAP_AF_TAG_A_VID_SEL,

    /**
     * {@code VCAP_AF_TAG_B_DEI_SEL = 82}
     */
    @EnumMember(
        value = 82L,
        name = "VCAP_AF_TAG_B_DEI_SEL"
    )
    VCAP_AF_TAG_B_DEI_SEL,

    /**
     * {@code VCAP_AF_TAG_B_PCP_SEL = 83}
     */
    @EnumMember(
        value = 83L,
        name = "VCAP_AF_TAG_B_PCP_SEL"
    )
    VCAP_AF_TAG_B_PCP_SEL,

    /**
     * {@code VCAP_AF_TAG_B_TPID_SEL = 84}
     */
    @EnumMember(
        value = 84L,
        name = "VCAP_AF_TAG_B_TPID_SEL"
    )
    VCAP_AF_TAG_B_TPID_SEL,

    /**
     * {@code VCAP_AF_TAG_B_VID_SEL = 85}
     */
    @EnumMember(
        value = 85L,
        name = "VCAP_AF_TAG_B_VID_SEL"
    )
    VCAP_AF_TAG_B_VID_SEL,

    /**
     * {@code VCAP_AF_TAG_C_DEI_SEL = 86}
     */
    @EnumMember(
        value = 86L,
        name = "VCAP_AF_TAG_C_DEI_SEL"
    )
    VCAP_AF_TAG_C_DEI_SEL,

    /**
     * {@code VCAP_AF_TAG_C_PCP_SEL = 87}
     */
    @EnumMember(
        value = 87L,
        name = "VCAP_AF_TAG_C_PCP_SEL"
    )
    VCAP_AF_TAG_C_PCP_SEL,

    /**
     * {@code VCAP_AF_TAG_C_TPID_SEL = 88}
     */
    @EnumMember(
        value = 88L,
        name = "VCAP_AF_TAG_C_TPID_SEL"
    )
    VCAP_AF_TAG_C_TPID_SEL,

    /**
     * {@code VCAP_AF_TAG_C_VID_SEL = 89}
     */
    @EnumMember(
        value = 89L,
        name = "VCAP_AF_TAG_C_VID_SEL"
    )
    VCAP_AF_TAG_C_VID_SEL,

    /**
     * {@code VCAP_AF_TYPE = 90}
     */
    @EnumMember(
        value = 90L,
        name = "VCAP_AF_TYPE"
    )
    VCAP_AF_TYPE,

    /**
     * {@code VCAP_AF_UNTAG_VID_ENA = 91}
     */
    @EnumMember(
        value = 91L,
        name = "VCAP_AF_UNTAG_VID_ENA"
    )
    VCAP_AF_UNTAG_VID_ENA,

    /**
     * {@code VCAP_AF_VID_A_VAL = 92}
     */
    @EnumMember(
        value = 92L,
        name = "VCAP_AF_VID_A_VAL"
    )
    VCAP_AF_VID_A_VAL,

    /**
     * {@code VCAP_AF_VID_B_VAL = 93}
     */
    @EnumMember(
        value = 93L,
        name = "VCAP_AF_VID_B_VAL"
    )
    VCAP_AF_VID_B_VAL,

    /**
     * {@code VCAP_AF_VID_C_VAL = 94}
     */
    @EnumMember(
        value = 94L,
        name = "VCAP_AF_VID_C_VAL"
    )
    VCAP_AF_VID_C_VAL,

    /**
     * {@code VCAP_AF_VID_REPLACE_ENA = 95}
     */
    @EnumMember(
        value = 95L,
        name = "VCAP_AF_VID_REPLACE_ENA"
    )
    VCAP_AF_VID_REPLACE_ENA,

    /**
     * {@code VCAP_AF_VID_VAL = 96}
     */
    @EnumMember(
        value = 96L,
        name = "VCAP_AF_VID_VAL"
    )
    VCAP_AF_VID_VAL,

    /**
     * {@code VCAP_AF_VLAN_POP_CNT = 97}
     */
    @EnumMember(
        value = 97L,
        name = "VCAP_AF_VLAN_POP_CNT"
    )
    VCAP_AF_VLAN_POP_CNT,

    /**
     * {@code VCAP_AF_VLAN_POP_CNT_ENA = 98}
     */
    @EnumMember(
        value = 98L,
        name = "VCAP_AF_VLAN_POP_CNT_ENA"
    )
    VCAP_AF_VLAN_POP_CNT_ENA
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_user"
  )
  public enum vcap_user implements Enum<vcap_user>, TypedEnum<vcap_user, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_USER_PTP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_USER_PTP"
    )
    VCAP_USER_PTP,

    /**
     * {@code VCAP_USER_MRP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_USER_MRP"
    )
    VCAP_USER_MRP,

    /**
     * {@code VCAP_USER_CFM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_USER_CFM"
    )
    VCAP_USER_CFM,

    /**
     * {@code VCAP_USER_VLAN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_USER_VLAN"
    )
    VCAP_USER_VLAN,

    /**
     * {@code VCAP_USER_QOS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_USER_QOS"
    )
    VCAP_USER_QOS,

    /**
     * {@code VCAP_USER_VCAP_UTIL = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCAP_USER_VCAP_UTIL"
    )
    VCAP_USER_VCAP_UTIL,

    /**
     * {@code VCAP_USER_TC = 6}
     */
    @EnumMember(
        value = 6L,
        name = "VCAP_USER_TC"
    )
    VCAP_USER_TC,

    /**
     * {@code VCAP_USER_TC_EXTRA = 7}
     */
    @EnumMember(
        value = 7L,
        name = "VCAP_USER_TC_EXTRA"
    )
    VCAP_USER_TC_EXTRA,

    /**
     * {@code __VCAP_USER_AFTER_LAST = 8}
     */
    @EnumMember(
        value = 8L,
        name = "__VCAP_USER_AFTER_LAST"
    )
    __VCAP_USER_AFTER_LAST,

    /**
     * {@code VCAP_USER_MAX = 7}
     */
    @EnumMember(
        value = 7L,
        name = "VCAP_USER_MAX"
    )
    VCAP_USER_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_statistics"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_statistics extends Struct {
    public String name;

    public int count;

    public Ptr<String> keyfield_set_names;

    public Ptr<String> actionfield_set_names;

    public Ptr<String> keyfield_names;

    public Ptr<String> actionfield_names;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_field"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_field extends Struct {
    public @Unsigned short type;

    public @Unsigned short width;

    public @Unsigned short offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_set"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_set extends Struct {
    public char type_id;

    public char sw_per_item;

    public char sw_cnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_typegroup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_typegroup extends Struct {
    public @Unsigned short offset;

    public @Unsigned short width;

    public @Unsigned short value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_info extends Struct {
    public String name;

    public @Unsigned short rows;

    public @Unsigned short sw_count;

    public @Unsigned short sw_width;

    public @Unsigned short sticky_width;

    public @Unsigned short act_width;

    public @Unsigned short default_cnt;

    public @Unsigned short require_cnt_dis;

    public @Unsigned short version;

    public Ptr<vcap_set> keyfield_set;

    public int keyfield_set_size;

    public Ptr<vcap_set> actionfield_set;

    public int actionfield_set_size;

    public Ptr<Ptr<vcap_field>> keyfield_set_map;

    public Ptr<java.lang.Integer> keyfield_set_map_size;

    public Ptr<Ptr<vcap_field>> actionfield_set_map;

    public Ptr<java.lang.Integer> actionfield_set_map_size;

    public Ptr<Ptr<vcap_typegroup>> keyfield_set_typegroups;

    public Ptr<Ptr<vcap_typegroup>> actionfield_set_typegroups;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_field_type"
  )
  public enum vcap_field_type implements Enum<vcap_field_type>, TypedEnum<vcap_field_type, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_FIELD_BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_FIELD_BIT"
    )
    VCAP_FIELD_BIT,

    /**
     * {@code VCAP_FIELD_U32 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_FIELD_U32"
    )
    VCAP_FIELD_U32,

    /**
     * {@code VCAP_FIELD_U48 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_FIELD_U48"
    )
    VCAP_FIELD_U48,

    /**
     * {@code VCAP_FIELD_U56 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_FIELD_U56"
    )
    VCAP_FIELD_U56,

    /**
     * {@code VCAP_FIELD_U64 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_FIELD_U64"
    )
    VCAP_FIELD_U64,

    /**
     * {@code VCAP_FIELD_U72 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCAP_FIELD_U72"
    )
    VCAP_FIELD_U72,

    /**
     * {@code VCAP_FIELD_U112 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "VCAP_FIELD_U112"
    )
    VCAP_FIELD_U112,

    /**
     * {@code VCAP_FIELD_U128 = 7}
     */
    @EnumMember(
        value = 7L,
        name = "VCAP_FIELD_U128"
    )
    VCAP_FIELD_U128
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_cache_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_cache_data extends Struct {
    public Ptr<java.lang. @Unsigned Integer> keystream;

    public Ptr<java.lang. @Unsigned Integer> maskstream;

    public Ptr<java.lang. @Unsigned Integer> actionstream;

    public @Unsigned int counter;

    public boolean sticky;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_selection"
  )
  public enum vcap_selection implements Enum<vcap_selection>, TypedEnum<vcap_selection, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_SEL_ENTRY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_SEL_ENTRY"
    )
    VCAP_SEL_ENTRY,

    /**
     * {@code VCAP_SEL_ACTION = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_SEL_ACTION"
    )
    VCAP_SEL_ACTION,

    /**
     * {@code VCAP_SEL_COUNTER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_SEL_COUNTER"
    )
    VCAP_SEL_COUNTER,

    /**
     * {@code VCAP_SEL_ALL = 255}
     */
    @EnumMember(
        value = 255L,
        name = "VCAP_SEL_ALL"
    )
    VCAP_SEL_ALL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_command"
  )
  public enum vcap_command implements Enum<vcap_command>, TypedEnum<vcap_command, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_CMD_WRITE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_CMD_WRITE"
    )
    VCAP_CMD_WRITE,

    /**
     * {@code VCAP_CMD_READ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_CMD_READ"
    )
    VCAP_CMD_READ,

    /**
     * {@code VCAP_CMD_MOVE_DOWN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_CMD_MOVE_DOWN"
    )
    VCAP_CMD_MOVE_DOWN,

    /**
     * {@code VCAP_CMD_MOVE_UP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_CMD_MOVE_UP"
    )
    VCAP_CMD_MOVE_UP,

    /**
     * {@code VCAP_CMD_INITIALIZE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_CMD_INITIALIZE"
    )
    VCAP_CMD_INITIALIZE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_rule_error"
  )
  public enum vcap_rule_error implements Enum<vcap_rule_error>, TypedEnum<vcap_rule_error, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_ERR_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_ERR_NONE"
    )
    VCAP_ERR_NONE,

    /**
     * {@code VCAP_ERR_NO_ADMIN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_ERR_NO_ADMIN"
    )
    VCAP_ERR_NO_ADMIN,

    /**
     * {@code VCAP_ERR_NO_NETDEV = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_ERR_NO_NETDEV"
    )
    VCAP_ERR_NO_NETDEV,

    /**
     * {@code VCAP_ERR_NO_KEYSET_MATCH = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_ERR_NO_KEYSET_MATCH"
    )
    VCAP_ERR_NO_KEYSET_MATCH,

    /**
     * {@code VCAP_ERR_NO_ACTIONSET_MATCH = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCAP_ERR_NO_ACTIONSET_MATCH"
    )
    VCAP_ERR_NO_ACTIONSET_MATCH,

    /**
     * {@code VCAP_ERR_NO_PORT_KEYSET_MATCH = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCAP_ERR_NO_PORT_KEYSET_MATCH"
    )
    VCAP_ERR_NO_PORT_KEYSET_MATCH
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_admin"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_admin extends Struct {
    public list_head list;

    public list_head rules;

    public list_head enabled;

    public mutex lock;

    public vcap_type vtype;

    public int vinst;

    public int first_cid;

    public int last_cid;

    public int tgt_inst;

    public int lookups;

    public int lookups_per_instance;

    public int last_valid_addr;

    public int first_valid_addr;

    public int last_used_addr;

    public boolean w32be;

    public boolean ingress;

    public vcap_cache_data cache;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_rule"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_rule extends Struct {
    public int vcap_chain_id;

    public vcap_user user;

    public @Unsigned short priority;

    public @Unsigned int id;

    public @Unsigned long cookie;

    public list_head keyfields;

    public list_head actionfields;

    public vcap_keyfield_set keyset;

    public vcap_actionfield_set actionset;

    public vcap_rule_error exterr;

    public @Unsigned long client;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_keyset_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_keyset_list extends Struct {
    public int max;

    public int cnt;

    public Ptr<vcap_keyfield_set> keysets;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_output_print"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_output_print extends Struct {
    public Ptr<?> prf;

    public Ptr<?> dst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_operations"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_operations extends Struct {
    public Ptr<?> validate_keyset;

    public Ptr<?> add_default_fields;

    public Ptr<?> cache_erase;

    public Ptr<?> cache_write;

    public Ptr<?> cache_read;

    public Ptr<?> init;

    public Ptr<?> update;

    public Ptr<?> move;

    public Ptr<?> port_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_control"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_control extends Struct {
    public Ptr<vcap_operations> ops;

    public Ptr<vcap_info> vcaps;

    public Ptr<vcap_statistics> stats;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_client_keyfield_ctrl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_client_keyfield_ctrl extends Struct {
    public list_head list;

    public vcap_key_field key;

    public vcap_field_type type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u1_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u1_key extends Struct {
    public char value;

    public char mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u32_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u32_key extends Struct {
    public @Unsigned int value;

    public @Unsigned int mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u48_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u48_key extends Struct {
    public char @Size(6) [] value;

    public char @Size(6) [] mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u56_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u56_key extends Struct {
    public char @Size(7) [] value;

    public char @Size(7) [] mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u64_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u64_key extends Struct {
    public char @Size(8) [] value;

    public char @Size(8) [] mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u72_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u72_key extends Struct {
    public char @Size(9) [] value;

    public char @Size(9) [] mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u112_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u112_key extends Struct {
    public char @Size(14) [] value;

    public char @Size(14) [] mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u128_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u128_key extends Struct {
    public char @Size(16) [] value;

    public char @Size(16) [] mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_client_keyfield_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_client_keyfield_data extends Struct {
    @InlineUnion(50919)
    public vcap_u1_key u1;

    @InlineUnion(50919)
    public vcap_u32_key u32;

    @InlineUnion(50919)
    public vcap_u48_key u48;

    @InlineUnion(50919)
    public vcap_u56_key u56;

    @InlineUnion(50919)
    public vcap_u64_key u64;

    @InlineUnion(50919)
    public vcap_u72_key u72;

    @InlineUnion(50919)
    public vcap_u112_key u112;

    @InlineUnion(50919)
    public vcap_u128_key u128;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_client_keyfield"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_client_keyfield extends Struct {
    public vcap_client_keyfield_ctrl ctrl;

    public vcap_client_keyfield_data data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_client_actionfield_ctrl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_client_actionfield_ctrl extends Struct {
    public list_head list;

    public vcap_action_field action;

    public vcap_field_type type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u1_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u1_action extends Struct {
    public char value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u32_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u32_action extends Struct {
    public @Unsigned int value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u48_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u48_action extends Struct {
    public char @Size(6) [] value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u56_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u56_action extends Struct {
    public char @Size(7) [] value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u64_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u64_action extends Struct {
    public char @Size(8) [] value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u72_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u72_action extends Struct {
    public char @Size(9) [] value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u112_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u112_action extends Struct {
    public char @Size(14) [] value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_u128_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_u128_action extends Struct {
    public char @Size(16) [] value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_client_actionfield_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_client_actionfield_data extends Struct {
    @InlineUnion(50931)
    public vcap_u1_action u1;

    @InlineUnion(50931)
    public vcap_u32_action u32;

    @InlineUnion(50931)
    public vcap_u48_action u48;

    @InlineUnion(50931)
    public vcap_u56_action u56;

    @InlineUnion(50931)
    public vcap_u64_action u64;

    @InlineUnion(50931)
    public vcap_u72_action u72;

    @InlineUnion(50931)
    public vcap_u112_action u112;

    @InlineUnion(50931)
    public vcap_u128_action u128;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_client_actionfield"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_client_actionfield extends Struct {
    public vcap_client_actionfield_ctrl ctrl;

    public vcap_client_actionfield_data data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_counter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_counter extends Struct {
    public @Unsigned int value;

    public boolean sticky;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_rule_state"
  )
  public enum vcap_rule_state implements Enum<vcap_rule_state>, TypedEnum<vcap_rule_state, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_RS_PERMANENT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_RS_PERMANENT"
    )
    VCAP_RS_PERMANENT,

    /**
     * {@code VCAP_RS_ENABLED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_RS_ENABLED"
    )
    VCAP_RS_ENABLED,

    /**
     * {@code VCAP_RS_DISABLED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_RS_DISABLED"
    )
    VCAP_RS_DISABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_rule_internal"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_rule_internal extends Struct {
    public vcap_rule data;

    public list_head list;

    public Ptr<vcap_admin> admin;

    public Ptr<net_device> ndev;

    public Ptr<vcap_control> vctrl;

    public @Unsigned int sort_key;

    public int keyset_sw;

    public int actionset_sw;

    public int keyset_sw_regs;

    public int actionset_sw_regs;

    public int size;

    public @Unsigned int addr;

    public @Unsigned int counter_id;

    public vcap_counter counter;

    public vcap_rule_state state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_admin_debugfs_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_admin_debugfs_info extends Struct {
    public Ptr<vcap_control> vctrl;

    public Ptr<vcap_admin> admin;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_port_debugfs_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_port_debugfs_info extends Struct {
    public Ptr<vcap_control> vctrl;

    public Ptr<net_device> ndev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_actionset_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_actionset_list extends Struct {
    public int max;

    public int cnt;

    public Ptr<vcap_actionfield_set> actionsets;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_bit"
  )
  public enum vcap_bit implements Enum<vcap_bit>, TypedEnum<vcap_bit, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_BIT_ANY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_BIT_ANY"
    )
    VCAP_BIT_ANY,

    /**
     * {@code VCAP_BIT_0 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_BIT_0"
    )
    VCAP_BIT_0,

    /**
     * {@code VCAP_BIT_1 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_BIT_1"
    )
    VCAP_BIT_1
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_stream_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_stream_iter extends Struct {
    public @Unsigned int offset;

    public @Unsigned int sw_width;

    public @Unsigned int regs_per_sw;

    public @Unsigned int reg_idx;

    public @Unsigned int reg_bitpos;

    public Ptr<vcap_typegroup> tg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_rule_move"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_rule_move extends Struct {
    public int addr;

    public int offset;

    public int count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_enabled_port"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_enabled_port extends Struct {
    public list_head list;

    public Ptr<net_device> ndev;

    public @Unsigned long cookie;

    public int src_cid;

    public int dst_cid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct vcap_tc_flower_parse_usage"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class vcap_tc_flower_parse_usage extends Struct {
    public Ptr<flow_cls_offload> fco;

    public Ptr<flow_rule> frule;

    public Ptr<vcap_rule> vrule;

    public Ptr<vcap_admin> admin;

    public @Unsigned short l3_proto;

    public char l4_proto;

    public @Unsigned short tpid;

    public @Unsigned long used_keys;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_is2_arp_opcode"
  )
  public enum vcap_is2_arp_opcode implements Enum<vcap_is2_arp_opcode>, TypedEnum<vcap_is2_arp_opcode, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_IS2_ARP_REQUEST = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_IS2_ARP_REQUEST"
    )
    VCAP_IS2_ARP_REQUEST,

    /**
     * {@code VCAP_IS2_ARP_REPLY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_IS2_ARP_REPLY"
    )
    VCAP_IS2_ARP_REPLY,

    /**
     * {@code VCAP_IS2_RARP_REQUEST = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_IS2_RARP_REQUEST"
    )
    VCAP_IS2_RARP_REQUEST,

    /**
     * {@code VCAP_IS2_RARP_REPLY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCAP_IS2_RARP_REPLY"
    )
    VCAP_IS2_RARP_REPLY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum vcap_arp_opcode"
  )
  public enum vcap_arp_opcode implements Enum<vcap_arp_opcode>, TypedEnum<vcap_arp_opcode, java.lang. @Unsigned Integer> {
    /**
     * {@code VCAP_ARP_OP_RESERVED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCAP_ARP_OP_RESERVED"
    )
    VCAP_ARP_OP_RESERVED,

    /**
     * {@code VCAP_ARP_OP_REQUEST = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCAP_ARP_OP_REQUEST"
    )
    VCAP_ARP_OP_REQUEST,

    /**
     * {@code VCAP_ARP_OP_REPLY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCAP_ARP_OP_REPLY"
    )
    VCAP_ARP_OP_REPLY
  }
}
