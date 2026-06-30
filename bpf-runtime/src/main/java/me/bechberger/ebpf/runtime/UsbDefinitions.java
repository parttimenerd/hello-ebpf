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
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
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
 * Generated class for BPF runtime types that start with usb
 */
@java.lang.SuppressWarnings("unused")
public final class UsbDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __usb_bus_reprobe_drivers(Ptr<device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__usb_create_hcd((const struct hc_driver *)$arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static Ptr<usb_hcd> __usb_create_hcd(Ptr<hc_driver> driver, Ptr<device> sysdev,
      Ptr<device> dev, String bus_name, Ptr<usb_hcd> primary_hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __usb_get_extra_descriptor(String buffer, @Unsigned int size, char type,
      Ptr<Ptr<?>> ptr, @Unsigned long minsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __usb_hcd_giveback_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __usb_phy_get_charger_type(Ptr<usb_phy> usb_phy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __usb_queue_reset_device(Ptr<work_struct> ws) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __usb_unanchor_urb(Ptr<urb> urb, Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __usb_wireless_status_intf(Ptr<work_struct> ws) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_acpi_add_usb4_devlink(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_acpi_bus_match(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<acpi_device> usb_acpi_find_companion(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<acpi_device> usb_acpi_get_companion_for_port(Ptr<usb_port> port_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_acpi_port_lpm_incapable(Ptr<usb_device> hdev, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_acpi_power_manageable(Ptr<usb_device> hdev, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_acpi_register() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_acpi_set_power_state(Ptr<usb_device> hdev, int index, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_acpi_unregister() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_add_hcd(Ptr<usb_hcd> hcd, @Unsigned int irqnum, @Unsigned long irqflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_add_phy(Ptr<usb_phy> x, usb_phy_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_add_phy_dev(Ptr<usb_phy> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> usb_alloc_coherent(Ptr<usb_device> dev, @Unsigned long size,
      @Unsigned @OriginalName("gfp_t") int mem_flags,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_device> usb_alloc_dev(Ptr<usb_device> parent, Ptr<usb_bus> bus,
      @Unsigned int port1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> usb_alloc_noncoherent(Ptr<usb_device> dev, @Unsigned long size,
      @Unsigned @OriginalName("gfp_t") int mem_flags,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma, dma_data_direction dir,
      Ptr<Ptr<sg_table>> table) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_alloc_streams(Ptr<usb_interface> _interface,
      Ptr<Ptr<usb_host_endpoint>> eps, @Unsigned int num_eps, @Unsigned int num_streams,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<urb> usb_alloc_urb(int iso_packets,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_altnum_to_altsetting((const struct usb_interface *)$arg1, $arg2)")
  public static Ptr<usb_host_interface> usb_altnum_to_altsetting(Ptr<usb_interface> intf,
      @Unsigned int altnum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_amd_dev_put() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_amd_find_chipset_info() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_amd_hang_symptom_quirk() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_amd_prefetch_quirk() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_amd_pt_check_port(Ptr<device> device, int port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_amd_quirk_pll(int disable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_amd_quirk_pll_check() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_amd_quirk_pll_disable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_amd_quirk_pll_enable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_anchor_empty(Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_anchor_resume_wakeups(Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_anchor_suspend_wakeups(Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_anchor_urb(Ptr<urb> urb, Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_api_blocking_completion(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_asmedia_modifyflowcontrol(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_asmedia_wait_write(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_authorize_device(Ptr<usb_device> usb_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_authorize_interface(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_autopm_get_interface(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_autopm_get_interface_async(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_autopm_get_interface_no_resume(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_autopm_put_interface(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_autopm_put_interface_async(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_autopm_put_interface_no_suspend(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_autoresume_device(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_autosuspend_device(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_block_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_bulk_msg(Ptr<usb_device> usb_dev, @Unsigned int pipe, Ptr<?> data, int len,
      Ptr<java.lang.Integer> actual_length, int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_bus_notify(Ptr<notifier_block> nb, @Unsigned long action, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String usb_cache_string(Ptr<usb_device> udev, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long usb_calc_bus_time(int speed, int is_input, int isoc, int bytecount) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_check_bulk_endpoints((const struct usb_interface *)$arg1, (const u8 *)$arg2)")
  public static boolean usb_check_bulk_endpoints(Ptr<usb_interface> intf,
      Ptr<java.lang.Character> ep_addrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_check_int_endpoints((const struct usb_interface *)$arg1, (const u8 *)$arg2)")
  public static boolean usb_check_int_endpoints(Ptr<usb_interface> intf,
      Ptr<java.lang.Character> ep_addrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_choose_configuration(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_clear_halt(Ptr<usb_device> dev, int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_clear_port_feature(Ptr<usb_device> hdev, int port1, int feature) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_common_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_common_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_control_msg(Ptr<usb_device> dev, @Unsigned int pipe, char request,
      char requesttype, @Unsigned short value, @Unsigned short index, Ptr<?> data,
      @Unsigned short size, int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_control_msg_recv(Ptr<usb_device> dev, char endpoint, char request,
      char requesttype, @Unsigned short value, @Unsigned short index, Ptr<?> driver_data,
      @Unsigned short size, int timeout, @Unsigned @OriginalName("gfp_t") int memflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_control_msg_send($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, (const void *)$arg7, $arg8, $arg9, $arg10)")
  public static int usb_control_msg_send(Ptr<usb_device> dev, char endpoint, char request,
      char requesttype, @Unsigned short value, @Unsigned short index, Ptr<?> driver_data,
      @Unsigned short size, int timeout, @Unsigned @OriginalName("gfp_t") int memflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_create_ep_devs(Ptr<device> parent, Ptr<usb_host_endpoint> endpoint,
      Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_create_hcd((const struct hc_driver *)$arg1, $arg2, (const u8 *)$arg3)")
  public static Ptr<usb_hcd> usb_create_hcd(Ptr<hc_driver> driver, Ptr<device> dev,
      String bus_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_create_shared_hcd((const struct hc_driver *)$arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static Ptr<usb_hcd> usb_create_shared_hcd(Ptr<hc_driver> driver, Ptr<device> dev,
      String bus_name, Ptr<usb_hcd> primary_hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_create_sysfs_dev_files(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_create_sysfs_intf_files(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_deauthorize_device(Ptr<usb_device> usb_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_deauthorize_interface(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)usb_decode_ctrl($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7))")
  public static String usb_decode_ctrl(String str, @Unsigned long size, char bRequestType,
      char bRequest, @Unsigned short wValue, @Unsigned short wIndex, @Unsigned short wLength) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_decode_ctrl_generic(String str, @Unsigned long size, char bRequestType,
      char bRequest, @Unsigned short wValue, @Unsigned short wIndex, @Unsigned short wLength) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_decode_ctrl_standard(String str, @Unsigned long size, char bRequestType,
      char bRequest, @Unsigned short wValue, @Unsigned short wIndex, @Unsigned short wLength) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_decode_interval((const struct usb_endpoint_descriptor *)$arg1, $arg2)")
  public static @Unsigned int usb_decode_interval(Ptr<usb_endpoint_descriptor> epd,
      usb_device_speed speed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_deregister(Ptr<usb_driver> driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_deregister_bus(Ptr<usb_bus> bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_deregister_dev(Ptr<usb_interface> intf,
      Ptr<usb_class_driver> class_driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_deregister_device_driver(Ptr<usb_device_driver> udriver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_destroy_configuration(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_detect_interface_quirks(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_detect_quirks(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_detect_static_quirks($arg1, (const struct usb_device_id *)$arg2)")
  public static @Unsigned int usb_detect_static_quirks(Ptr<usb_device> udev,
      Ptr<usb_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_dev_complete(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_dev_freeze(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_dev_poweroff(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_dev_prepare(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_dev_restore(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_dev_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_dev_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_dev_thaw(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_dev_uevent((const struct device *)$arg1, $arg2)")
  public static int usb_dev_uevent(Ptr<device> dev, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long usb_device_dump(Ptr<String> buffer,
      Ptr<java.lang. @Unsigned Long> nbytes,
      Ptr<java.lang. @OriginalName("loff_t") Long> skip_bytes,
      Ptr<java.lang. @OriginalName("loff_t") Long> file_offset, Ptr<usb_device> usbdev,
      Ptr<usb_bus> bus, int level, int index, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_device_is_owned(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_device_match($arg1, (const struct device_driver *)$arg2)")
  public static int usb_device_match(Ptr<device> dev, Ptr<device_driver> drv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct usb_device_id*)usb_device_match_id($arg1, (const struct usb_device_id *)$arg2))")
  public static Ptr<usb_device_id> usb_device_match_id(Ptr<usb_device> udev,
      Ptr<usb_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_device_may_initiate_lpm(Ptr<usb_device> udev, usb3_link_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long usb_device_read(Ptr<file> file, String buf,
      @Unsigned long nbytes, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_device_supports_lpm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_devio_cleanup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_devio_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_disable_autosuspend(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_disable_device(Ptr<usb_device> dev, int skip_ep0) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_disable_device_endpoints(Ptr<usb_device> dev, int skip_ep0) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_disable_endpoint(Ptr<usb_device> dev, @Unsigned int epaddr,
      boolean reset_hardware) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_disable_interface(Ptr<usb_device> dev, Ptr<usb_interface> intf,
      boolean reset_hardware) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_disable_link_state(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      usb3_link_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_disable_lpm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_disable_ltm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_disable_remote_wakeup(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_disable_usb2_hardware_lpm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_disable_xhci_ports(Ptr<pci_dev> xhci_pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_disabled() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_disconnect(Ptr<Ptr<usb_device>> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_driver_applicable($arg1, (const struct usb_device_driver *)$arg2)")
  public static boolean usb_driver_applicable(Ptr<usb_device> udev, Ptr<usb_device_driver> udrv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_driver_claim_interface(Ptr<usb_driver> driver, Ptr<usb_interface> iface,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_driver_release_interface(Ptr<usb_driver> driver,
      Ptr<usb_interface> iface) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_driver_set_configuration(Ptr<usb_device> udev, int config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_dump_config($arg1, $arg2, $arg3, (const struct usb_host_config *)$arg4, $arg5)")
  public static String usb_dump_config(int speed, String start, String end,
      Ptr<usb_host_config> config, int active) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String usb_dump_desc(String start, String end, Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_enable_autosuspend(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_enable_endpoint(Ptr<usb_device> dev, Ptr<usb_host_endpoint> ep,
      boolean reset_ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_enable_intel_xhci_ports(Ptr<pci_dev> xhci_pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_enable_interface(Ptr<usb_device> dev, Ptr<usb_interface> intf,
      boolean reset_eps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_enable_link_state(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      usb3_link_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_enable_lpm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_enable_ltm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_enable_usb2_hardware_lpm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_endpoint_is_ignored(Ptr<usb_device> udev, Ptr<usb_host_interface> intf,
      Ptr<usb_endpoint_descriptor> epd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_ep0_reinit(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)usb_ep_type_string($arg1))")
  public static String usb_ep_type_string(int ep_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_host_interface> usb_find_alt_setting(Ptr<usb_host_config> config,
      @Unsigned int iface_num, @Unsigned int alt_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_find_common_endpoints(Ptr<usb_host_interface> alt,
      Ptr<Ptr<usb_endpoint_descriptor>> bulk_in, Ptr<Ptr<usb_endpoint_descriptor>> bulk_out,
      Ptr<Ptr<usb_endpoint_descriptor>> int_in, Ptr<Ptr<usb_endpoint_descriptor>> int_out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_find_common_endpoints_reverse(Ptr<usb_host_interface> alt,
      Ptr<Ptr<usb_endpoint_descriptor>> bulk_in, Ptr<Ptr<usb_endpoint_descriptor>> bulk_out,
      Ptr<Ptr<usb_endpoint_descriptor>> int_in, Ptr<Ptr<usb_endpoint_descriptor>> int_out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_interface> usb_find_interface(Ptr<usb_driver> drv, int minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_for_each_dev($arg1, (int (*)(struct usb_device*, void*))$arg2)")
  public static int usb_for_each_dev(Ptr<?> data, Ptr<?> fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_forced_unbind_intf(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_free_coherent(Ptr<usb_device> dev, @Unsigned long size, Ptr<?> addr,
      @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_free_noncoherent(Ptr<usb_device> dev, @Unsigned long size, Ptr<?> addr,
      dma_data_direction dir, Ptr<sg_table> table) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_free_streams(Ptr<usb_interface> _interface, Ptr<Ptr<usb_host_endpoint>> eps,
      @Unsigned int num_eps, @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_free_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_generic_driver_disconnect(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean usb_generic_driver_match(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_generic_driver_probe(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_generic_driver_resume(Ptr<usb_device> udev,
      @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_generic_driver_suspend(Ptr<usb_device> udev,
      @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_get_bos_descriptor(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_get_configuration(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_get_current_frame_number(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_get_descriptor(Ptr<usb_device> dev, char type, char index, Ptr<?> buf,
      int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_device> usb_get_dev(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_device_descriptor> usb_get_device_descriptor(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static usb_dr_mode usb_get_dr_mode(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<urb> usb_get_from_anchor(Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_hcd> usb_get_hcd(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("acpi_handle") Ptr<?> usb_get_hub_port_acpi_handle(
      Ptr<usb_device> hdev, int port1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_interface> usb_get_intf(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static usb_device_speed usb_get_maximum_speed(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static usb_ssp_rate usb_get_maximum_ssp_rate(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_phy> usb_get_phy(usb_phy_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static usb_dr_mode usb_get_role_switch_default_mode(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_get_status(Ptr<usb_device> dev, int recip, int type, int target,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_get_string(Ptr<usb_device> dev, @Unsigned short langid, char index,
      Ptr<?> buf, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<urb> usb_get_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_giveback_urb_bh(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hc_died(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_alloc_bandwidth(Ptr<usb_device> udev, Ptr<usb_host_config> new_config,
      Ptr<usb_host_interface> cur_alt, Ptr<usb_host_interface> new_alt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_amd_remote_wakeup_quirk(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_check_unlink_urb(Ptr<usb_hcd> hcd, Ptr<urb> urb, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_disable_endpoint(Ptr<usb_device> udev, Ptr<usb_host_endpoint> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_end_port_resume(Ptr<usb_bus> bus, int portnum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_find_raw_port_number(Ptr<usb_hcd> hcd, int port1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_flush_endpoint(Ptr<usb_device> udev, Ptr<usb_host_endpoint> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_get_frame_number(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_giveback_urb(Ptr<usb_hcd> hcd, Ptr<urb> urb, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn usb_hcd_irq(int irq, Ptr<?> __hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_is_primary_hcd(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_link_urb_to_ep(Ptr<usb_hcd> hcd, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_map_urb_for_dma(Ptr<usb_hcd> hcd, Ptr<urb> urb,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_hcd_pci_probe($arg1, (const struct hc_driver *)$arg2)")
  public static int usb_hcd_pci_probe(Ptr<pci_dev> dev, Ptr<hc_driver> driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_pci_remove(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_pci_shutdown(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_platform_shutdown(Ptr<platform_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_poll_rh_status(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_reset_endpoint(Ptr<usb_device> udev, Ptr<usb_host_endpoint> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_resume_root_hub(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_setup_local_mem(Ptr<usb_hcd> hcd,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_start_port_resume(Ptr<usb_bus> bus, int portnum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_submit_urb(Ptr<urb> urb,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_synchronize_unlinks(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hcd_unlink_urb(Ptr<urb> urb, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_unlink_urb_from_ep(Ptr<usb_hcd> hcd, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_unmap_urb_for_dma(Ptr<usb_hcd> hcd, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hcd_unmap_urb_setup_for_dma(Ptr<usb_hcd> hcd, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hub_adjust_deviceremovable(Ptr<usb_device> hdev,
      Ptr<usb_hub_descriptor> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hub_claim_port(Ptr<usb_device> hdev, @Unsigned int port1,
      Ptr<usb_dev_state> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hub_cleanup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hub_clear_tt_buffer(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hub_create_port_device(Ptr<usb_hub> hub, int port1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_device> usb_hub_find_child(Ptr<usb_device> hdev, int port1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hub_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hub_port_status(Ptr<usb_hub> hub, int port1,
      Ptr<java.lang. @Unsigned Short> status, Ptr<java.lang. @Unsigned Short> change) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hub_release_all_ports(Ptr<usb_device> hdev, Ptr<usb_dev_state> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hub_release_port(Ptr<usb_device> hdev, @Unsigned int port1,
      Ptr<usb_dev_state> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_hub_remove_port_device(Ptr<usb_hub> hub, int port1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_hub_set_port_power(Ptr<usb_device> hdev, Ptr<usb_hub> hub, int port1,
      boolean set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_hub> usb_hub_to_struct_hub(Ptr<usb_device> hdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_if_uevent((const struct device *)$arg1, $arg2)")
  public static int usb_if_uevent(Ptr<device> dev, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_ifnum_to_if((const struct usb_device *)$arg1, $arg2)")
  public static Ptr<usb_interface> usb_ifnum_to_if(Ptr<usb_device> dev, @Unsigned int ifnum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_init_pool_max() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_init_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_interrupt_msg(Ptr<usb_device> usb_dev, @Unsigned int pipe, Ptr<?> data,
      int len, Ptr<java.lang.Integer> actual_length, int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<device> usb_intf_get_dma_device(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_kick_hub_wq(Ptr<usb_device> hdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_kill_anchored_urbs(Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_kill_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_led_activity(usb_led_event ev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_lock_device_for_reset($arg1, (const struct usb_interface *)$arg2)")
  public static int usb_lock_device_for_reset(Ptr<usb_device> udev, Ptr<usb_interface> iface) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_major_cleanup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_major_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_match_device($arg1, (const struct usb_device_id *)$arg2)")
  public static int usb_match_device(Ptr<usb_device> dev, Ptr<usb_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct usb_device_id*)usb_match_dynamic_id($arg1, (const struct usb_driver *)$arg2))")
  public static Ptr<usb_device_id> usb_match_dynamic_id(Ptr<usb_interface> intf,
      Ptr<usb_driver> drv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct usb_device_id*)usb_match_id($arg1, (const struct usb_device_id *)$arg2))")
  public static Ptr<usb_device_id> usb_match_id(Ptr<usb_interface> _interface,
      Ptr<usb_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_match_one_id($arg1, (const struct usb_device_id *)$arg2)")
  public static int usb_match_one_id(Ptr<usb_interface> _interface, Ptr<usb_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_match_one_id_intf($arg1, $arg2, (const struct usb_device_id *)$arg3)")
  public static int usb_match_one_id_intf(Ptr<usb_device> dev, Ptr<usb_host_interface> intf,
      Ptr<usb_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_mon_deregister() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_mon_register((const struct usb_mon_operations *)$arg1)")
  public static int usb_mon_register(Ptr<usb_mon_operations> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_new_device(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_notify_add_bus(Ptr<usb_bus> ubus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_notify_add_device(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_notify_remove_bus(Ptr<usb_bus> ubus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_notify_remove_device(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)usb_otg_state_string($arg1))")
  public static String usb_otg_state_string(usb_otg_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_parse_configuration(Ptr<usb_device> dev, int cfgidx,
      Ptr<usb_host_config> config, String buffer, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_parse_endpoint(Ptr<device> ddev, int cfgno, Ptr<usb_host_config> config,
      int inum, int asnum, Ptr<usb_host_interface> ifp, int num_ep, String buffer, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_parse_interface(Ptr<device> ddev, int cfgno, Ptr<usb_host_config> config,
      String buffer, int size, Ptr<java.lang.Character> inums, Ptr<java.lang.Character> nalts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_parse_ss_endpoint_companion(Ptr<device> ddev, int cfgno, int inum,
      int asnum, Ptr<usb_host_endpoint> ep, String buffer, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_parse_ssp_isoc_endpoint_companion(Ptr<device> ddev, int cfgno, int inum,
      int asnum, Ptr<usb_host_endpoint> ep, String buffer, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_phy_get_charger_current(Ptr<usb_phy> usb_phy,
      Ptr<java.lang. @Unsigned Integer> min, Ptr<java.lang. @Unsigned Integer> max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_phy_notify_charger_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_phy_roothub> usb_phy_roothub_alloc(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_phy_roothub> usb_phy_roothub_alloc_usb3_phy(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_calibrate(Ptr<usb_phy_roothub> phy_roothub) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_exit(Ptr<usb_phy_roothub> phy_roothub) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_init(Ptr<usb_phy_roothub> phy_roothub) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_notify_connect(Ptr<usb_phy_roothub> phy_roothub, int port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_notify_disconnect(Ptr<usb_phy_roothub> phy_roothub, int port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_phy_roothub_power_off(Ptr<usb_phy_roothub> phy_roothub) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_power_on(Ptr<usb_phy_roothub> phy_roothub) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_resume(Ptr<device> controller_dev,
      Ptr<usb_phy_roothub> phy_roothub) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_set_mode(Ptr<usb_phy_roothub> phy_roothub, phy_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_phy_roothub_suspend(Ptr<device> controller_dev,
      Ptr<usb_phy_roothub> phy_roothub) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_phy_set_charger_current(Ptr<usb_phy> usb_phy, @Unsigned int mA) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_phy_set_charger_state(Ptr<usb_phy> usb_phy, usb_charger_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_phy_set_event(Ptr<usb_phy> x, @Unsigned long event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_phy_uevent((const struct device *)$arg1, $arg2)")
  public static int usb_phy_uevent(Ptr<device> dev, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_pipe_type_check(Ptr<usb_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_poison_anchored_urbs(Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_poison_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_port_device_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_port_disable(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_port_is_power_on(Ptr<usb_hub> hub, @Unsigned int portstatus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_port_resume(Ptr<usb_device> udev,
      @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_port_runtime_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_port_runtime_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_port_shutdown(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_port_suspend(Ptr<usb_device> udev,
      @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_probe_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_probe_interface(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_put_dev(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_put_hcd(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_put_intf(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_put_invalidate_rhdev(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_put_phy(Ptr<usb_phy> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_queue_reset_device(Ptr<usb_interface> iface) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_register_dev(Ptr<usb_interface> intf, Ptr<usb_class_driver> class_driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_register_device_driver(Ptr<usb_device_driver> new_udriver,
      Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_register_driver($arg1, $arg2, (const u8 *)$arg3)")
  public static int usb_register_driver(Ptr<usb_driver> new_driver, Ptr<module> owner,
      String mod_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_register_notify(Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_release_bos_descriptor(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_release_dev(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_release_interface(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_release_interface_cache(Ptr<kref> ref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_release_quirk_list() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_remote_wakeup(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_remove_device(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_remove_ep_devs(Ptr<usb_host_endpoint> endpoint) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_remove_hcd(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_remove_phy(Ptr<usb_phy> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_remove_sysfs_dev_files(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_remove_sysfs_intf_files(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_req_set_sel(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_reset_and_verify_device(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_reset_configuration(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_reset_device(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_reset_endpoint(Ptr<usb_device> dev, @Unsigned int epaddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_resume(Ptr<device> dev, @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_resume_both(Ptr<usb_device> udev,
      @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_resume_complete(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)usb_role_string($arg1))")
  public static String usb_role_string(usb_role role) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_role_switch_find_by_fwnode((const struct fwnode_handle *)$arg1)")
  public static Ptr<usb_role_switch> usb_role_switch_find_by_fwnode(Ptr<fwnode_handle> fwnode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_role_switch> usb_role_switch_get(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> usb_role_switch_get_drvdata(Ptr<usb_role_switch> sw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static usb_role usb_role_switch_get_role(Ptr<usb_role_switch> sw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_role_switch> usb_role_switch_is_parent(Ptr<fwnode_handle> fwnode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short usb_role_switch_is_visible(
      Ptr<kobject> kobj, Ptr<attribute> attr, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_role_switch_match((const struct fwnode_handle *)$arg1, (const u8 *)$arg2, $arg3)")
  public static Ptr<?> usb_role_switch_match(Ptr<fwnode_handle> fwnode, String id, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_role_switch_put(Ptr<usb_role_switch> sw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_role_switch_register($arg1, (const struct usb_role_switch_desc *)$arg2)")
  public static Ptr<usb_role_switch> usb_role_switch_register(Ptr<device> parent,
      Ptr<usb_role_switch_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_role_switch_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_role_switch_set_drvdata(Ptr<usb_role_switch> sw, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_role_switch_set_role(Ptr<usb_role_switch> sw, usb_role role) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_role_switch_uevent((const struct device *)$arg1, $arg2)")
  public static int usb_role_switch_uevent(Ptr<device> dev, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_role_switch_unregister(Ptr<usb_role_switch> sw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_roles_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_roles_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_root_hub_lost_power(Ptr<usb_device> rhdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_runtime_idle(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_runtime_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_runtime_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_scuttle_anchored_urbs(Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_set_configuration(Ptr<usb_device> dev, int configuration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_set_device_initiated_lpm(Ptr<usb_device> udev, usb3_link_state state,
      boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_set_device_state(Ptr<usb_device> udev, usb_device_state new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_set_interface(Ptr<usb_device> dev, int _interface, int alternate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_set_isoch_delay(Ptr<usb_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_set_lpm_parameters(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_set_lpm_timeout(Ptr<usb_device> udev, usb3_link_state state, int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_set_wireless_status(Ptr<usb_interface> iface, usb_wireless_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_sg_cancel(Ptr<usb_sg_request> io) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_sg_init(Ptr<usb_sg_request> io, Ptr<usb_device> dev, @Unsigned int pipe,
      @Unsigned int period, Ptr<scatterlist> sg, int nents, @Unsigned long length,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_sg_wait(Ptr<usb_sg_request> io) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long usb_show_dynids(Ptr<usb_dynids> dynids, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_shutdown_interface(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)usb_speed_string($arg1))")
  public static String usb_speed_string(usb_device_speed speed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_start_wait_urb(Ptr<urb> urb, int timeout,
      Ptr<java.lang.Integer> actual_length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)usb_state_string($arg1))")
  public static String usb_state_string(usb_device_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_stop_hcd(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_store_new_id($arg1, (const struct usb_device_id *)$arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static @OriginalName("ssize_t") long usb_store_new_id(Ptr<usb_dynids> dynids,
      Ptr<usb_device_id> id_table, Ptr<device_driver> driver, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_string(Ptr<usb_device> dev, int index, String buf, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_string_sub(Ptr<usb_device> dev, @Unsigned int langid, @Unsigned int index,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_submit_urb(Ptr<urb> urb, @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_suspend(Ptr<device> dev, @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_suspend_both(Ptr<usb_device> udev,
      @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_uevent((const struct device *)$arg1, $arg2)")
  public static int usb_uevent(Ptr<device> dev, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_unanchor_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_unbind_and_rebind_marked_interfaces(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_unbind_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_unbind_interface(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_unlink_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_unlocked_disable_lpm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_unlocked_enable_lpm(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_unpoison_anchored_urbs(Ptr<usb_anchor> anchor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_unpoison_urb(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_unregister_notify(Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_update_wireless_status_attr(Ptr<usb_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("usb_urb_ep_type_check((const struct urb *)$arg1)")
  public static int usb_urb_ep_type_check(Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int usb_wait_anchor_empty_timeout(Ptr<usb_anchor> anchor, @Unsigned int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int usb_wakeup_enabled_descendants(Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void usb_wakeup_notification(Ptr<usb_device> hdev, @Unsigned int portnum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int serial_number; long long unsigned int reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_of_device_path_of_edd_device_params extends Struct {
    public @Unsigned long serial_number;

    public @Unsigned long reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_device_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_device_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public @Unsigned @OriginalName("__le16") short bcdUSB;

    public char bDeviceClass;

    public char bDeviceSubClass;

    public char bDeviceProtocol;

    public char bMaxPacketSize0;

    public @Unsigned @OriginalName("__le16") short idVendor;

    public @Unsigned @OriginalName("__le16") short idProduct;

    public @Unsigned @OriginalName("__le16") short bcdDevice;

    public char iManufacturer;

    public char iProduct;

    public char iSerialNumber;

    public char bNumConfigurations;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_config_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_config_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public @Unsigned @OriginalName("__le16") short wTotalLength;

    public char bNumInterfaces;

    public char bConfigurationValue;

    public char iConfiguration;

    public char bmAttributes;

    public char bMaxPower;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_interface_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_interface_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bInterfaceNumber;

    public char bAlternateSetting;

    public char bNumEndpoints;

    public char bInterfaceClass;

    public char bInterfaceSubClass;

    public char bInterfaceProtocol;

    public char iInterface;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_endpoint_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_endpoint_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bEndpointAddress;

    public char bmAttributes;

    public @Unsigned @OriginalName("__le16") short wMaxPacketSize;

    public char bInterval;

    public char bRefresh;

    public char bSynchAddress;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_eusb2_isoc_ep_comp_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_eusb2_isoc_ep_comp_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public @Unsigned @OriginalName("__le16") short wMaxPacketSize;

    public @Unsigned @OriginalName("__le32") int dwBytesPerInterval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ssp_isoc_ep_comp_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ssp_isoc_ep_comp_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public @Unsigned @OriginalName("__le16") short wReseved;

    public @Unsigned @OriginalName("__le32") int dwBytesPerInterval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ss_ep_comp_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ss_ep_comp_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bMaxBurst;

    public char bmAttributes;

    public @Unsigned @OriginalName("__le16") short wBytesPerInterval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_interface_assoc_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_interface_assoc_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bFirstInterface;

    public char bInterfaceCount;

    public char bFunctionClass;

    public char bFunctionSubClass;

    public char bFunctionProtocol;

    public char iFunction;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_bos_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_bos_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public @Unsigned @OriginalName("__le16") short wTotalLength;

    public char bNumDeviceCaps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ext_cap_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ext_cap_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDevCapabilityType;

    public @Unsigned @OriginalName("__le32") int bmAttributes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ss_cap_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ss_cap_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDevCapabilityType;

    public char bmAttributes;

    public @Unsigned @OriginalName("__le16") short wSpeedSupported;

    public char bFunctionalitySupport;

    public char bU1devExitLat;

    public @Unsigned @OriginalName("__le16") short bU2DevExitLat;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ss_container_id_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ss_container_id_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDevCapabilityType;

    public char bReserved;

    public char @Size(16) [] ContainerID;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ssp_cap_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ssp_cap_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDevCapabilityType;

    public char bReserved;

    public @Unsigned @OriginalName("__le32") int bmAttributes;

    public @Unsigned @OriginalName("__le16") short wFunctionalitySupport;

    public @Unsigned @OriginalName("__le16") short wReserved;

    @InlineUnion(41838)
    public @Unsigned @OriginalName("__le32") int legacy_padding;

    @InlineUnion(41838)
    public anon_member_of_anon_member_of_usb_ssp_cap_descriptor anon7$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ptm_cap_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ptm_cap_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDevCapabilityType;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_device_speed"
  )
  public enum usb_device_speed implements Enum<usb_device_speed>, TypedEnum<usb_device_speed, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_SPEED_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_SPEED_UNKNOWN"
    )
    USB_SPEED_UNKNOWN,

    /**
     * {@code USB_SPEED_LOW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_SPEED_LOW"
    )
    USB_SPEED_LOW,

    /**
     * {@code USB_SPEED_FULL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_SPEED_FULL"
    )
    USB_SPEED_FULL,

    /**
     * {@code USB_SPEED_HIGH = 3}
     */
    @EnumMember(
        value = 3L,
        name = "USB_SPEED_HIGH"
    )
    USB_SPEED_HIGH,

    /**
     * {@code USB_SPEED_WIRELESS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "USB_SPEED_WIRELESS"
    )
    USB_SPEED_WIRELESS,

    /**
     * {@code USB_SPEED_SUPER = 5}
     */
    @EnumMember(
        value = 5L,
        name = "USB_SPEED_SUPER"
    )
    USB_SPEED_SUPER,

    /**
     * {@code USB_SPEED_SUPER_PLUS = 6}
     */
    @EnumMember(
        value = 6L,
        name = "USB_SPEED_SUPER_PLUS"
    )
    USB_SPEED_SUPER_PLUS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_device_state"
  )
  public enum usb_device_state implements Enum<usb_device_state>, TypedEnum<usb_device_state, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_STATE_NOTATTACHED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_STATE_NOTATTACHED"
    )
    USB_STATE_NOTATTACHED,

    /**
     * {@code USB_STATE_ATTACHED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_STATE_ATTACHED"
    )
    USB_STATE_ATTACHED,

    /**
     * {@code USB_STATE_POWERED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_STATE_POWERED"
    )
    USB_STATE_POWERED,

    /**
     * {@code USB_STATE_RECONNECTING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "USB_STATE_RECONNECTING"
    )
    USB_STATE_RECONNECTING,

    /**
     * {@code USB_STATE_UNAUTHENTICATED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "USB_STATE_UNAUTHENTICATED"
    )
    USB_STATE_UNAUTHENTICATED,

    /**
     * {@code USB_STATE_DEFAULT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "USB_STATE_DEFAULT"
    )
    USB_STATE_DEFAULT,

    /**
     * {@code USB_STATE_ADDRESS = 6}
     */
    @EnumMember(
        value = 6L,
        name = "USB_STATE_ADDRESS"
    )
    USB_STATE_ADDRESS,

    /**
     * {@code USB_STATE_CONFIGURED = 7}
     */
    @EnumMember(
        value = 7L,
        name = "USB_STATE_CONFIGURED"
    )
    USB_STATE_CONFIGURED,

    /**
     * {@code USB_STATE_SUSPENDED = 8}
     */
    @EnumMember(
        value = 8L,
        name = "USB_STATE_SUSPENDED"
    )
    USB_STATE_SUSPENDED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_ssp_rate"
  )
  public enum usb_ssp_rate implements Enum<usb_ssp_rate>, TypedEnum<usb_ssp_rate, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_SSP_GEN_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_SSP_GEN_UNKNOWN"
    )
    USB_SSP_GEN_UNKNOWN,

    /**
     * {@code USB_SSP_GEN_2x1 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_SSP_GEN_2x1"
    )
    USB_SSP_GEN_2x1,

    /**
     * {@code USB_SSP_GEN_1x2 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_SSP_GEN_1x2"
    )
    USB_SSP_GEN_1x2,

    /**
     * {@code USB_SSP_GEN_2x2 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "USB_SSP_GEN_2x2"
    )
    USB_SSP_GEN_2x2
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_host_endpoint"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_host_endpoint extends Struct {
    public usb_endpoint_descriptor desc;

    public usb_ss_ep_comp_descriptor ss_ep_comp;

    public usb_ssp_isoc_ep_comp_descriptor ssp_isoc_ep_comp;

    public usb_eusb2_isoc_ep_comp_descriptor eusb2_isoc_ep_comp;

    public list_head urb_list;

    public Ptr<?> hcpriv;

    public Ptr<ep_device> ep_dev;

    public String extra;

    public int extralen;

    public int enabled;

    public int streams;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_host_interface"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_host_interface extends Struct {
    public usb_interface_descriptor desc;

    public int extralen;

    public String extra;

    public Ptr<usb_host_endpoint> endpoint;

    public String string;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_interface_condition"
  )
  public enum usb_interface_condition implements Enum<usb_interface_condition>, TypedEnum<usb_interface_condition, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_INTERFACE_UNBOUND = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_INTERFACE_UNBOUND"
    )
    USB_INTERFACE_UNBOUND,

    /**
     * {@code USB_INTERFACE_BINDING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_INTERFACE_BINDING"
    )
    USB_INTERFACE_BINDING,

    /**
     * {@code USB_INTERFACE_BOUND = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_INTERFACE_BOUND"
    )
    USB_INTERFACE_BOUND,

    /**
     * {@code USB_INTERFACE_UNBINDING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "USB_INTERFACE_UNBINDING"
    )
    USB_INTERFACE_UNBINDING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_wireless_status"
  )
  public enum usb_wireless_status implements Enum<usb_wireless_status>, TypedEnum<usb_wireless_status, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_WIRELESS_STATUS_NA = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_WIRELESS_STATUS_NA"
    )
    USB_WIRELESS_STATUS_NA,

    /**
     * {@code USB_WIRELESS_STATUS_DISCONNECTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_WIRELESS_STATUS_DISCONNECTED"
    )
    USB_WIRELESS_STATUS_DISCONNECTED,

    /**
     * {@code USB_WIRELESS_STATUS_CONNECTED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_WIRELESS_STATUS_CONNECTED"
    )
    USB_WIRELESS_STATUS_CONNECTED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_interface"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_interface extends Struct {
    public Ptr<usb_host_interface> altsetting;

    public Ptr<usb_host_interface> cur_altsetting;

    public @Unsigned int num_altsetting;

    public Ptr<usb_interface_assoc_descriptor> intf_assoc;

    public int minor;

    public usb_interface_condition condition;

    public @Unsigned int sysfs_files_created;

    public @Unsigned int ep_devs_created;

    public @Unsigned int unregistering;

    public @Unsigned int needs_remote_wakeup;

    public @Unsigned int needs_altsetting0;

    public @Unsigned int needs_binding;

    public @Unsigned int resetting_device;

    public @Unsigned int authorized;

    public usb_wireless_status wireless_status;

    public work_struct wireless_status_work;

    public device dev;

    public Ptr<device> usb_dev;

    public work_struct reset_ws;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_interface_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_interface_cache extends Struct {
    public @Unsigned int num_altsetting;

    public kref ref;

    public usb_host_interface @Size(0) [] altsetting;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_host_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_host_config extends Struct {
    public usb_config_descriptor desc;

    public String string;

    public Ptr<usb_interface_assoc_descriptor> @Size(16) [] intf_assoc;

    public Ptr<usb_interface> @Size(32) [] _interface;

    public Ptr<usb_interface_cache> @Size(32) [] intf_cache;

    public String extra;

    public int extralen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_host_bos"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_host_bos extends Struct {
    public Ptr<usb_bos_descriptor> desc;

    public Ptr<usb_ext_cap_descriptor> ext_cap;

    public Ptr<usb_ss_cap_descriptor> ss_cap;

    public Ptr<usb_ssp_cap_descriptor> ssp_cap;

    public Ptr<usb_ss_container_id_descriptor> ss_id;

    public Ptr<usb_ptm_cap_descriptor> ptm_cap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_bus"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_bus extends Struct {
    public Ptr<device> controller;

    public Ptr<device> sysdev;

    public int busnum;

    public String bus_name;

    public char uses_pio_for_control;

    public char otg_port;

    public @Unsigned int is_b_host;

    public @Unsigned int b_hnp_enable;

    public @Unsigned int no_stop_on_short;

    public @Unsigned int no_sg_constraint;

    public @Unsigned int sg_tablesize;

    public int devnum_next;

    public mutex devnum_next_mutex;

    public @Unsigned long @Size(2) [] devmap;

    public Ptr<usb_device> root_hub;

    public Ptr<usb_bus> hs_companion;

    public int bandwidth_allocated;

    public int bandwidth_int_reqs;

    public int bandwidth_isoc_reqs;

    public @Unsigned int resuming_ports;

    public @OriginalName("mon_bus") Ptr<?> mon_bus;

    public int monitored;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_device extends Struct {
    public int devnum;

    public char @Size(16) [] devpath;

    public @Unsigned int route;

    public usb_device_state state;

    public usb_device_speed speed;

    public @Unsigned int rx_lanes;

    public @Unsigned int tx_lanes;

    public usb_ssp_rate ssp_rate;

    public Ptr<usb_tt> tt;

    public int ttport;

    public @Unsigned int @Size(2) [] toggle;

    public Ptr<usb_device> parent;

    public Ptr<usb_bus> bus;

    public usb_host_endpoint ep0;

    public device dev;

    public usb_device_descriptor descriptor;

    public Ptr<usb_host_bos> bos;

    public Ptr<usb_host_config> config;

    public Ptr<usb_host_config> actconfig;

    public Ptr<usb_host_endpoint> @Size(16) [] ep_in;

    public Ptr<usb_host_endpoint> @Size(16) [] ep_out;

    public Ptr<String> rawdescriptors;

    public @Unsigned short bus_mA;

    public char portnum;

    public char level;

    public char devaddr;

    public @Unsigned int can_submit;

    public @Unsigned int persist_enabled;

    public @Unsigned int reset_in_progress;

    public @Unsigned int have_langid;

    public @Unsigned int authorized;

    public @Unsigned int authenticated;

    public @Unsigned int lpm_capable;

    public @Unsigned int lpm_devinit_allow;

    public @Unsigned int usb2_hw_lpm_capable;

    public @Unsigned int usb2_hw_lpm_besl_capable;

    public @Unsigned int usb2_hw_lpm_enabled;

    public @Unsigned int usb2_hw_lpm_allowed;

    public @Unsigned int usb3_lpm_u1_enabled;

    public @Unsigned int usb3_lpm_u2_enabled;

    public int string_langid;

    public String product;

    public String manufacturer;

    public String serial;

    public list_head filelist;

    public int maxchild;

    public @Unsigned int quirks;

    public atomic_t urbnum;

    public @Unsigned long active_duration;

    public @Unsigned long connect_time;

    public @Unsigned int do_remote_wakeup;

    public @Unsigned int reset_resume;

    public @Unsigned int port_is_suspended;

    public usb_link_tunnel_mode tunnel_mode;

    public Ptr<device_link> usb4_link;

    public int slot_id;

    public usb2_lpm_parameters l1_params;

    public usb3_lpm_parameters u1_params;

    public usb3_lpm_parameters u2_params;

    public @Unsigned int lpm_disable_count;

    public @Unsigned short hub_delay;

    public @Unsigned int use_generic_driver;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_link_tunnel_mode"
  )
  public enum usb_link_tunnel_mode implements Enum<usb_link_tunnel_mode>, TypedEnum<usb_link_tunnel_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_LINK_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_LINK_UNKNOWN"
    )
    USB_LINK_UNKNOWN,

    /**
     * {@code USB_LINK_NATIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_LINK_NATIVE"
    )
    USB_LINK_NATIVE,

    /**
     * {@code USB_LINK_TUNNELED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_LINK_TUNNELED"
    )
    USB_LINK_TUNNELED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_tt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_tt extends Struct {
    public Ptr<usb_device> hub;

    public int multi;

    public @Unsigned int think_time;

    public Ptr<?> hcpriv;

    public @OriginalName("spinlock_t") spinlock lock;

    public list_head clear_list;

    public work_struct clear_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_iso_packet_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_iso_packet_descriptor extends Struct {
    public @Unsigned int offset;

    public @Unsigned int length;

    public @Unsigned int actual_length;

    public int status;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_anchor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_anchor extends Struct {
    public list_head urb_list;

    public @OriginalName("wait_queue_head_t") wait_queue_head wait;

    public @OriginalName("spinlock_t") spinlock lock;

    public atomic_t suspend_wakeups;

    public @Unsigned int poisoned;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_dev_authorize_policy"
  )
  public enum usb_dev_authorize_policy implements Enum<usb_dev_authorize_policy>, TypedEnum<usb_dev_authorize_policy, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_DEVICE_AUTHORIZE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_DEVICE_AUTHORIZE_NONE"
    )
    USB_DEVICE_AUTHORIZE_NONE,

    /**
     * {@code USB_DEVICE_AUTHORIZE_ALL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_DEVICE_AUTHORIZE_ALL"
    )
    USB_DEVICE_AUTHORIZE_ALL,

    /**
     * {@code USB_DEVICE_AUTHORIZE_INTERNAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_DEVICE_AUTHORIZE_INTERNAL"
    )
    USB_DEVICE_AUTHORIZE_INTERNAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_hcd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_hcd extends Struct {
    public usb_bus self;

    public kref kref;

    public String product_desc;

    public int speed;

    public char @Size(24) [] irq_descr;

    public timer_list rh_timer;

    public Ptr<urb> status_urb;

    public work_struct wakeup_work;

    public work_struct died_work;

    public Ptr<hc_driver> driver;

    public Ptr<usb_phy> usb_phy;

    public Ptr<usb_phy_roothub> phy_roothub;

    public @Unsigned long flags;

    public usb_dev_authorize_policy dev_policy;

    public @Unsigned int rh_registered;

    public @Unsigned int rh_pollable;

    public @Unsigned int msix_enabled;

    public @Unsigned int msi_enabled;

    public @Unsigned int skip_phy_initialization;

    public @Unsigned int uses_new_polling;

    public @Unsigned int has_tt;

    public @Unsigned int amd_resume_bug;

    public @Unsigned int can_do_streams;

    public @Unsigned int tpl_support;

    public @Unsigned int cant_recv_wakeups;

    public @Unsigned int irq;

    public Ptr<?> regs;

    public @Unsigned @OriginalName("resource_size_t") long rsrc_start;

    public @Unsigned @OriginalName("resource_size_t") long rsrc_len;

    public @Unsigned int power_budget;

    public giveback_urb_bh high_prio_bh;

    public giveback_urb_bh low_prio_bh;

    public Ptr<mutex> address0_mutex;

    public Ptr<mutex> bandwidth_mutex;

    public Ptr<usb_hcd> shared_hcd;

    public Ptr<usb_hcd> primary_hcd;

    public Ptr<dma_pool> @Size(4) [] pool;

    public int state;

    public Ptr<gen_pool> localmem_pool;

    public @Unsigned long @Size(0) [] hcd_priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_otg_state"
  )
  public enum usb_otg_state implements Enum<usb_otg_state>, TypedEnum<usb_otg_state, java.lang. @Unsigned Integer> {
    /**
     * {@code OTG_STATE_UNDEFINED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OTG_STATE_UNDEFINED"
    )
    OTG_STATE_UNDEFINED,

    /**
     * {@code OTG_STATE_B_IDLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OTG_STATE_B_IDLE"
    )
    OTG_STATE_B_IDLE,

    /**
     * {@code OTG_STATE_B_SRP_INIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OTG_STATE_B_SRP_INIT"
    )
    OTG_STATE_B_SRP_INIT,

    /**
     * {@code OTG_STATE_B_PERIPHERAL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OTG_STATE_B_PERIPHERAL"
    )
    OTG_STATE_B_PERIPHERAL,

    /**
     * {@code OTG_STATE_B_WAIT_ACON = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OTG_STATE_B_WAIT_ACON"
    )
    OTG_STATE_B_WAIT_ACON,

    /**
     * {@code OTG_STATE_B_HOST = 5}
     */
    @EnumMember(
        value = 5L,
        name = "OTG_STATE_B_HOST"
    )
    OTG_STATE_B_HOST,

    /**
     * {@code OTG_STATE_A_IDLE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "OTG_STATE_A_IDLE"
    )
    OTG_STATE_A_IDLE,

    /**
     * {@code OTG_STATE_A_WAIT_VRISE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "OTG_STATE_A_WAIT_VRISE"
    )
    OTG_STATE_A_WAIT_VRISE,

    /**
     * {@code OTG_STATE_A_WAIT_BCON = 8}
     */
    @EnumMember(
        value = 8L,
        name = "OTG_STATE_A_WAIT_BCON"
    )
    OTG_STATE_A_WAIT_BCON,

    /**
     * {@code OTG_STATE_A_HOST = 9}
     */
    @EnumMember(
        value = 9L,
        name = "OTG_STATE_A_HOST"
    )
    OTG_STATE_A_HOST,

    /**
     * {@code OTG_STATE_A_SUSPEND = 10}
     */
    @EnumMember(
        value = 10L,
        name = "OTG_STATE_A_SUSPEND"
    )
    OTG_STATE_A_SUSPEND,

    /**
     * {@code OTG_STATE_A_PERIPHERAL = 11}
     */
    @EnumMember(
        value = 11L,
        name = "OTG_STATE_A_PERIPHERAL"
    )
    OTG_STATE_A_PERIPHERAL,

    /**
     * {@code OTG_STATE_A_WAIT_VFALL = 12}
     */
    @EnumMember(
        value = 12L,
        name = "OTG_STATE_A_WAIT_VFALL"
    )
    OTG_STATE_A_WAIT_VFALL,

    /**
     * {@code OTG_STATE_A_VBUS_ERR = 13}
     */
    @EnumMember(
        value = 13L,
        name = "OTG_STATE_A_VBUS_ERR"
    )
    OTG_STATE_A_VBUS_ERR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_dr_mode"
  )
  public enum usb_dr_mode implements Enum<usb_dr_mode>, TypedEnum<usb_dr_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_DR_MODE_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_DR_MODE_UNKNOWN"
    )
    USB_DR_MODE_UNKNOWN,

    /**
     * {@code USB_DR_MODE_HOST = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_DR_MODE_HOST"
    )
    USB_DR_MODE_HOST,

    /**
     * {@code USB_DR_MODE_PERIPHERAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_DR_MODE_PERIPHERAL"
    )
    USB_DR_MODE_PERIPHERAL,

    /**
     * {@code USB_DR_MODE_OTG = 3}
     */
    @EnumMember(
        value = 3L,
        name = "USB_DR_MODE_OTG"
    )
    USB_DR_MODE_OTG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_led_event"
  )
  public enum usb_led_event implements Enum<usb_led_event>, TypedEnum<usb_led_event, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_LED_EVENT_HOST = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_LED_EVENT_HOST"
    )
    USB_LED_EVENT_HOST,

    /**
     * {@code USB_LED_EVENT_GADGET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_LED_EVENT_GADGET"
    )
    USB_LED_EVENT_GADGET
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_device_id"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_device_id extends Struct {
    public @Unsigned short match_flags;

    public @Unsigned short idVendor;

    public @Unsigned short idProduct;

    public @Unsigned short bcdDevice_lo;

    public @Unsigned short bcdDevice_hi;

    public char bDeviceClass;

    public char bDeviceSubClass;

    public char bDeviceProtocol;

    public char bInterfaceClass;

    public char bInterfaceSubClass;

    public char bInterfaceProtocol;

    public char bInterfaceNumber;

    public @Unsigned @OriginalName("kernel_ulong_t") long driver_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_descriptor_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_descriptor_header extends Struct {
    public char bLength;

    public char bDescriptorType;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_port_connect_type"
  )
  public enum usb_port_connect_type implements Enum<usb_port_connect_type>, TypedEnum<usb_port_connect_type, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_PORT_CONNECT_TYPE_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_PORT_CONNECT_TYPE_UNKNOWN"
    )
    USB_PORT_CONNECT_TYPE_UNKNOWN,

    /**
     * {@code USB_PORT_CONNECT_TYPE_HOT_PLUG = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_PORT_CONNECT_TYPE_HOT_PLUG"
    )
    USB_PORT_CONNECT_TYPE_HOT_PLUG,

    /**
     * {@code USB_PORT_CONNECT_TYPE_HARD_WIRED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_PORT_CONNECT_TYPE_HARD_WIRED"
    )
    USB_PORT_CONNECT_TYPE_HARD_WIRED,

    /**
     * {@code USB_PORT_NOT_USED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "USB_PORT_NOT_USED"
    )
    USB_PORT_NOT_USED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_dynids"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_dynids extends Struct {
    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_driver extends Struct {
    public String name;

    public Ptr<?> probe;

    public Ptr<?> disconnect;

    public Ptr<?> unlocked_ioctl;

    public Ptr<?> suspend;

    public Ptr<?> resume;

    public Ptr<?> reset_resume;

    public Ptr<?> pre_reset;

    public Ptr<?> post_reset;

    public Ptr<?> shutdown;

    public Ptr<usb_device_id> id_table;

    public Ptr<Ptr<attribute_group>> dev_groups;

    public usb_dynids dynids;

    public device_driver driver;

    public @Unsigned int no_dynamic_id;

    public @Unsigned int supports_autosuspend;

    public @Unsigned int disable_hub_initiated_lpm;

    public @Unsigned int soft_unbind;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_device_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_device_driver extends Struct {
    public String name;

    public Ptr<?> match;

    public Ptr<?> probe;

    public Ptr<?> disconnect;

    public Ptr<?> suspend;

    public Ptr<?> resume;

    public Ptr<?> choose_configuration;

    public Ptr<Ptr<attribute_group>> dev_groups;

    public device_driver driver;

    public Ptr<usb_device_id> id_table;

    public @Unsigned int supports_autosuspend;

    public @Unsigned int generic_subclass;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_phy"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_phy extends Struct {
    public Ptr<device> dev;

    public String label;

    public @Unsigned int flags;

    public usb_phy_type type;

    public usb_phy_events last_event;

    public Ptr<usb_otg> otg;

    public Ptr<device> io_dev;

    public Ptr<usb_phy_io_ops> io_ops;

    public Ptr<?> io_priv;

    public Ptr<extcon_dev> edev;

    public Ptr<extcon_dev> id_edev;

    public notifier_block vbus_nb;

    public notifier_block id_nb;

    public notifier_block type_nb;

    public usb_charger_type chg_type;

    public usb_charger_state chg_state;

    public usb_charger_current chg_cur;

    public work_struct chg_work;

    public atomic_notifier_head notifier;

    public @Unsigned short port_status;

    public @Unsigned short port_change;

    public list_head head;

    public Ptr<?> init;

    public Ptr<?> shutdown;

    public Ptr<?> set_vbus;

    public Ptr<?> set_power;

    public Ptr<?> set_suspend;

    public Ptr<?> set_wakeup;

    public Ptr<?> notify_connect;

    public Ptr<?> notify_disconnect;

    public Ptr<?> charger_detect;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_port_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_port_status extends Struct {
    public @Unsigned @OriginalName("__le16") short wPortStatus;

    public @Unsigned @OriginalName("__le16") short wPortChange;

    public @Unsigned @OriginalName("__le32") int dwExtPortStatus;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_hub_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_hub_status extends Struct {
    public @Unsigned @OriginalName("__le16") short wHubStatus;

    public @Unsigned @OriginalName("__le16") short wHubChange;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_hub_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_hub_descriptor extends Struct {
    public char bDescLength;

    public char bDescriptorType;

    public char bNbrPorts;

    public @Unsigned @OriginalName("__le16") short wHubCharacteristics;

    public char bPwrOn2PwrGood;

    public char bHubContrCurrent;

    public u_of_usb_hub_descriptor u;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_charger_type"
  )
  public enum usb_charger_type implements Enum<usb_charger_type>, TypedEnum<usb_charger_type, java.lang. @Unsigned Integer> {
    /**
     * {@code UNKNOWN_TYPE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "UNKNOWN_TYPE"
    )
    UNKNOWN_TYPE,

    /**
     * {@code SDP_TYPE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SDP_TYPE"
    )
    SDP_TYPE,

    /**
     * {@code DCP_TYPE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DCP_TYPE"
    )
    DCP_TYPE,

    /**
     * {@code CDP_TYPE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "CDP_TYPE"
    )
    CDP_TYPE,

    /**
     * {@code ACA_TYPE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ACA_TYPE"
    )
    ACA_TYPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_charger_state"
  )
  public enum usb_charger_state implements Enum<usb_charger_state>, TypedEnum<usb_charger_state, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_CHARGER_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_CHARGER_DEFAULT"
    )
    USB_CHARGER_DEFAULT,

    /**
     * {@code USB_CHARGER_PRESENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_CHARGER_PRESENT"
    )
    USB_CHARGER_PRESENT,

    /**
     * {@code USB_CHARGER_ABSENT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_CHARGER_ABSENT"
    )
    USB_CHARGER_ABSENT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_phy_events"
  )
  public enum usb_phy_events implements Enum<usb_phy_events>, TypedEnum<usb_phy_events, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_EVENT_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_EVENT_NONE"
    )
    USB_EVENT_NONE,

    /**
     * {@code USB_EVENT_VBUS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_EVENT_VBUS"
    )
    USB_EVENT_VBUS,

    /**
     * {@code USB_EVENT_ID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_EVENT_ID"
    )
    USB_EVENT_ID,

    /**
     * {@code USB_EVENT_CHARGER = 3}
     */
    @EnumMember(
        value = 3L,
        name = "USB_EVENT_CHARGER"
    )
    USB_EVENT_CHARGER,

    /**
     * {@code USB_EVENT_ENUMERATED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "USB_EVENT_ENUMERATED"
    )
    USB_EVENT_ENUMERATED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_phy_type"
  )
  public enum usb_phy_type implements Enum<usb_phy_type>, TypedEnum<usb_phy_type, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_PHY_TYPE_UNDEFINED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_PHY_TYPE_UNDEFINED"
    )
    USB_PHY_TYPE_UNDEFINED,

    /**
     * {@code USB_PHY_TYPE_USB2 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_PHY_TYPE_USB2"
    )
    USB_PHY_TYPE_USB2,

    /**
     * {@code USB_PHY_TYPE_USB3 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_PHY_TYPE_USB3"
    )
    USB_PHY_TYPE_USB3
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_phy_io_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_phy_io_ops extends Struct {
    public Ptr<?> read;

    public Ptr<?> write;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_charger_current"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_charger_current extends Struct {
    public @Unsigned int sdp_min;

    public @Unsigned int sdp_max;

    public @Unsigned int dcp_min;

    public @Unsigned int dcp_max;

    public @Unsigned int cdp_min;

    public @Unsigned int cdp_max;

    public @Unsigned int aca_min;

    public @Unsigned int aca_max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_otg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_otg extends Struct {
    public char default_a;

    public Ptr<phy> phy;

    public Ptr<usb_phy> usb_phy;

    public Ptr<usb_bus> host;

    public Ptr<usb_gadget> gadget;

    public usb_otg_state state;

    public Ptr<?> set_host;

    public Ptr<?> set_peripheral;

    public Ptr<?> set_vbus;

    public Ptr<?> start_srp;

    public Ptr<?> start_hnp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_hub"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_hub extends Struct {
    public Ptr<device> intfdev;

    public Ptr<usb_device> hdev;

    public kref kref;

    public Ptr<urb> urb;

    public Ptr<char @Size(8) []> buffer;

    public Ptr<status_of_usb_hub> status;

    public mutex status_mutex;

    public int error;

    public int nerrors;

    public @Unsigned long @Size(1) [] event_bits;

    public @Unsigned long @Size(1) [] change_bits;

    public @Unsigned long @Size(1) [] removed_bits;

    public @Unsigned long @Size(1) [] wakeup_bits;

    public @Unsigned long @Size(1) [] power_bits;

    public @Unsigned long @Size(1) [] child_usage_bits;

    public @Unsigned long @Size(1) [] warm_reset_bits;

    public Ptr<usb_hub_descriptor> descriptor;

    public usb_tt tt;

    public @Unsigned int mA_per_port;

    public @Unsigned int wakeup_enabled_descendants;

    public @Unsigned int limited_power;

    public @Unsigned int quiescing;

    public @Unsigned int disconnected;

    public @Unsigned int in_reset;

    public @Unsigned int quirk_disable_autosuspend;

    public @Unsigned int quirk_check_port_auto_suspend;

    public @Unsigned int has_indicators;

    public char @Size(31) [] indicator;

    public delayed_work leds;

    public delayed_work init_work;

    public delayed_work post_resume_work;

    public work_struct events;

    public @OriginalName("spinlock_t") spinlock irq_urb_lock;

    public timer_list irq_urb_retry;

    public Ptr<Ptr<usb_port>> ports;

    public list_head onboard_devs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_port"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_port extends Struct {
    public Ptr<usb_device> child;

    public device dev;

    public Ptr<usb_dev_state> port_owner;

    public Ptr<usb_port> peer;

    public Ptr<typec_connector> connector;

    public Ptr<dev_pm_qos_request> req;

    public usb_port_connect_type connect_type;

    public usb_device_state state;

    public Ptr<kernfs_node> state_kn;

    public @Unsigned @OriginalName("usb_port_location_t") int location;

    public mutex status_lock;

    public @Unsigned int over_current_count;

    public char portnum;

    public @Unsigned int quirks;

    public @Unsigned int early_stop;

    public @Unsigned int ignore_event;

    public @Unsigned int is_superspeed;

    public @Unsigned int usb3_lpm_u1_permit;

    public @Unsigned int usb3_lpm_u2_permit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_qualifier_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_qualifier_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public @Unsigned @OriginalName("__le16") short bcdUSB;

    public char bDeviceClass;

    public char bDeviceSubClass;

    public char bDeviceProtocol;

    public char bMaxPacketSize0;

    public char bNumConfigurations;

    public char bRESERVED;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_set_sel_req"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_set_sel_req extends Struct {
    public char u1_sel;

    public char u1_pel;

    public @Unsigned @OriginalName("__le16") short u2_sel;

    public @Unsigned @OriginalName("__le16") short u2_pel;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_tt_clear"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_tt_clear extends Struct {
    public list_head clear_list;

    public @Unsigned int tt;

    public @Unsigned short devinfo;

    public Ptr<usb_hcd> hcd;

    public Ptr<usb_host_endpoint> ep;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ctrlrequest"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ctrlrequest extends Struct {
    public char bRequestType;

    public char bRequest;

    public @Unsigned @OriginalName("__le16") short wValue;

    public @Unsigned @OriginalName("__le16") short wIndex;

    public @Unsigned @OriginalName("__le16") short wLength;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_mon_operations"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_mon_operations extends Struct {
    public Ptr<?> urb_submit;

    public Ptr<?> urb_submit_error;

    public Ptr<?> urb_complete;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_sg_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_sg_request extends Struct {
    public int status;

    public @Unsigned long bytes;

    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<usb_device> dev;

    public int pipe;

    public int entries;

    public Ptr<Ptr<urb>> urbs;

    public int count;

    public completion complete;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_header_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_header_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public @Unsigned @OriginalName("__le16") short bcdCDC;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_call_mgmt_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_call_mgmt_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public char bmCapabilities;

    public char bDataInterface;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_acm_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_acm_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public char bmCapabilities;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_union_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_union_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public char bMasterInterface0;

    public char bSlaveInterface0;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_country_functional_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_country_functional_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public char iCountryCodeRelDate;

    public @Unsigned @OriginalName("__le16") short wCountyCode0;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_network_terminal_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_network_terminal_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public char bEntityId;

    public char iName;

    public char bChannelIndex;

    public char bPhysicalInterface;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_ether_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_ether_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public char iMACAddress;

    public @Unsigned @OriginalName("__le32") int bmEthernetStatistics;

    public @Unsigned @OriginalName("__le16") short wMaxSegmentSize;

    public @Unsigned @OriginalName("__le16") short wNumberMCFilters;

    public char bNumberPowerFilters;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_dmm_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_dmm_desc extends Struct {
    public char bFunctionLength;

    public char bDescriptorType;

    public char bDescriptorSubtype;

    public @Unsigned short bcdVersion;

    public @Unsigned @OriginalName("__le16") short wMaxCommand;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_mdlm_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_mdlm_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public @Unsigned @OriginalName("__le16") short bcdVersion;

    public char @Size(16) [] bGUID;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_mdlm_detail_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_mdlm_detail_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public char bGuidDescriptorType;

    public char @Size(0) [] bDetailData;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_obex_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_obex_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public @Unsigned @OriginalName("__le16") short bcdVersion;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_ncm_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_ncm_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public @Unsigned @OriginalName("__le16") short bcdNcmVersion;

    public char bmNetworkCapabilities;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_mbim_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_mbim_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public @Unsigned @OriginalName("__le16") short bcdMBIMVersion;

    public @Unsigned @OriginalName("__le16") short wMaxControlMessage;

    public char bNumberFilters;

    public char bMaxFilterSize;

    public @Unsigned @OriginalName("__le16") short wMaxSegmentSize;

    public char bmNetworkCapabilities;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_mbim_extended_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_mbim_extended_desc extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDescriptorSubType;

    public @Unsigned @OriginalName("__le16") short bcdMBIMExtendedVersion;

    public char bMaxOutstandingCommandMessages;

    public @Unsigned @OriginalName("__le16") short wMTU;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_cdc_parsed_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_cdc_parsed_header extends Struct {
    public Ptr<usb_cdc_union_desc> usb_cdc_union_desc;

    public Ptr<usb_cdc_header_desc> usb_cdc_header_desc;

    public Ptr<usb_cdc_call_mgmt_descriptor> usb_cdc_call_mgmt_descriptor;

    public Ptr<usb_cdc_acm_descriptor> usb_cdc_acm_descriptor;

    public Ptr<usb_cdc_country_functional_desc> usb_cdc_country_functional_desc;

    public Ptr<usb_cdc_network_terminal_desc> usb_cdc_network_terminal_desc;

    public Ptr<usb_cdc_ether_desc> usb_cdc_ether_desc;

    public Ptr<usb_cdc_dmm_desc> usb_cdc_dmm_desc;

    public Ptr<usb_cdc_mdlm_desc> usb_cdc_mdlm_desc;

    public Ptr<usb_cdc_mdlm_detail_desc> usb_cdc_mdlm_detail_desc;

    public Ptr<usb_cdc_obex_desc> usb_cdc_obex_desc;

    public Ptr<usb_cdc_ncm_desc> usb_cdc_ncm_desc;

    public Ptr<usb_cdc_mbim_desc> usb_cdc_mbim_desc;

    public Ptr<usb_cdc_mbim_extended_desc> usb_cdc_mbim_extended_desc;

    public boolean phonet_magic_present;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_dynid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_dynid extends Struct {
    public list_head node;

    public usb_device_id id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_dev_cap_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_dev_cap_header extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDevCapabilityType;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_class_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_class_driver extends Struct {
    public String name;

    public Ptr<?> devnode;

    public Ptr<file_operations> fops;

    public int minor_base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_dev_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_dev_state extends Struct {
    public list_head list;

    public Ptr<usb_device> dev;

    public Ptr<file> file;

    public @OriginalName("spinlock_t") spinlock lock;

    public list_head async_pending;

    public list_head async_completed;

    public list_head memory_list;

    public @OriginalName("wait_queue_head_t") wait_queue_head wait;

    public @OriginalName("wait_queue_head_t") wait_queue_head wait_for_resume;

    public @Unsigned int discsignr;

    public Ptr<pid> disc_pid;

    public Ptr<cred> cred;

    public @OriginalName("sigval_t") sigval disccontext;

    public @Unsigned long ifclaimed;

    public @Unsigned int disabled_bulk_eps;

    public @Unsigned long interface_allowed_mask;

    public int not_yet_resumed;

    public boolean suspend_allowed;

    public boolean privileges_dropped;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_memory"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_memory extends Struct {
    public list_head memlist;

    public int vma_use_count;

    public int urb_use_count;

    public @Unsigned int size;

    public Ptr<?> mem;

    public @Unsigned @OriginalName("dma_addr_t") long dma_handle;

    public @Unsigned long vm_start;

    public Ptr<usb_dev_state> ps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_phy_roothub"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_phy_roothub extends Struct {
    public Ptr<phy> phy;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_request extends Struct {
    public Ptr<usb_ep> ep;

    public Ptr<?> buf;

    public @Unsigned int length;

    public @Unsigned @OriginalName("dma_addr_t") long dma;

    public Ptr<scatterlist> sg;

    public @Unsigned int num_sgs;

    public @Unsigned int num_mapped_sgs;

    public @Unsigned int stream_id;

    public @Unsigned int is_last;

    public @Unsigned int no_interrupt;

    public @Unsigned int zero;

    public @Unsigned int short_not_ok;

    public @Unsigned int dma_mapped;

    public @Unsigned int sg_was_mapped;

    public Ptr<?> complete;

    public Ptr<?> context;

    public list_head list;

    public @Unsigned int frame_number;

    public int status;

    public @Unsigned int actual;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ep"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ep extends Struct {
    public Ptr<?> driver_data;

    public String name;

    public Ptr<usb_ep_ops> ops;

    public Ptr<usb_endpoint_descriptor> desc;

    public Ptr<usb_ss_ep_comp_descriptor> comp_desc;

    public list_head ep_list;

    public usb_ep_caps caps;

    public boolean claimed;

    public boolean enabled;

    public @Unsigned int mult;

    public @Unsigned int maxburst;

    public char address;

    public @Unsigned short maxpacket;

    public @Unsigned short maxpacket_limit;

    public @Unsigned short max_streams;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ep_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ep_ops extends Struct {
    public Ptr<?> enable;

    public Ptr<?> disable;

    public Ptr<?> dispose;

    public Ptr<?> alloc_request;

    public Ptr<?> free_request;

    public Ptr<?> queue;

    public Ptr<?> dequeue;

    public Ptr<?> set_halt;

    public Ptr<?> set_wedge;

    public Ptr<?> fifo_status;

    public Ptr<?> fifo_flush;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ep_caps"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ep_caps extends Struct {
    public @Unsigned int type_control;

    public @Unsigned int type_iso;

    public @Unsigned int type_bulk;

    public @Unsigned int type_int;

    public @Unsigned int dir_in;

    public @Unsigned int dir_out;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_dcd_config_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_dcd_config_params extends Struct {
    public char bU1devExitLat;

    public @Unsigned @OriginalName("__le16") short bU2DevExitLat;

    public char besl_baseline;

    public char besl_deep;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_gadget_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_gadget_ops extends Struct {
    public Ptr<?> get_frame;

    public Ptr<?> wakeup;

    public Ptr<?> func_wakeup;

    public Ptr<?> set_remote_wakeup;

    public Ptr<?> set_selfpowered;

    public Ptr<?> vbus_session;

    public Ptr<?> vbus_draw;

    public Ptr<?> pullup;

    public Ptr<?> ioctl;

    public Ptr<?> get_config_params;

    public Ptr<?> udc_start;

    public Ptr<?> udc_stop;

    public Ptr<?> udc_set_speed;

    public Ptr<?> udc_set_ssp_rate;

    public Ptr<?> udc_async_callbacks;

    public Ptr<?> match_ep;

    public Ptr<?> check_config;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_gadget"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_gadget extends Struct {
    public work_struct work;

    public @OriginalName("usb_udc") Ptr<?> udc;

    public Ptr<usb_gadget_ops> ops;

    public Ptr<usb_ep> ep0;

    public list_head ep_list;

    public usb_device_speed speed;

    public usb_device_speed max_speed;

    public usb_ssp_rate ssp_rate;

    public usb_ssp_rate max_ssp_rate;

    public usb_device_state state;

    public @OriginalName("spinlock_t") spinlock state_lock;

    public boolean teardown;

    public String name;

    public device dev;

    public @Unsigned int isoch_delay;

    public @Unsigned int out_epnum;

    public @Unsigned int in_epnum;

    public @Unsigned int mA;

    public Ptr<usb_otg_caps> otg_caps;

    public @Unsigned int sg_supported;

    public @Unsigned int is_otg;

    public @Unsigned int is_a_peripheral;

    public @Unsigned int b_hnp_enable;

    public @Unsigned int a_hnp_support;

    public @Unsigned int a_alt_hnp_support;

    public @Unsigned int hnp_polling_support;

    public @Unsigned int host_request_flag;

    public @Unsigned int quirk_ep_out_aligned_size;

    public @Unsigned int quirk_altset_not_supp;

    public @Unsigned int quirk_stall_not_supp;

    public @Unsigned int quirk_zlp_not_supp;

    public @Unsigned int quirk_avoids_skb_reserve;

    public @Unsigned int is_selfpowered;

    public @Unsigned int deactivated;

    public @Unsigned int connected;

    public @Unsigned int lpm_capable;

    public @Unsigned int wakeup_capable;

    public @Unsigned int wakeup_armed;

    public int irq;

    public int id_number;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_gadget_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_gadget_driver extends Struct {
    public String function;

    public usb_device_speed max_speed;

    public Ptr<?> bind;

    public Ptr<?> unbind;

    public Ptr<?> setup;

    public Ptr<?> disconnect;

    public Ptr<?> suspend;

    public Ptr<?> resume;

    public Ptr<?> reset;

    public device_driver driver;

    public String udc_name;

    public @Unsigned int match_existing_only;

    public boolean is_bound;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_otg_caps"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_otg_caps extends Struct {
    public @Unsigned short otg_rev;

    public boolean hnp_support;

    public boolean srp_support;

    public boolean adp_support;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum usb_role"
  )
  public enum usb_role implements Enum<usb_role>, TypedEnum<usb_role, java.lang. @Unsigned Integer> {
    /**
     * {@code USB_ROLE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "USB_ROLE_NONE"
    )
    USB_ROLE_NONE,

    /**
     * {@code USB_ROLE_HOST = 1}
     */
    @EnumMember(
        value = 1L,
        name = "USB_ROLE_HOST"
    )
    USB_ROLE_HOST,

    /**
     * {@code USB_ROLE_DEVICE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "USB_ROLE_DEVICE"
    )
    USB_ROLE_DEVICE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_role_switch_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_role_switch_desc extends Struct {
    public Ptr<fwnode_handle> fwnode;

    public Ptr<device> usb2_port;

    public Ptr<device> usb3_port;

    public Ptr<device> udc;

    public @OriginalName("usb_role_switch_set_t") Ptr<?> set;

    public @OriginalName("usb_role_switch_get_t") Ptr<?> get;

    public boolean allow_userspace_control;

    public Ptr<?> driver_data;

    public String name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ehci_pdata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ehci_pdata extends Struct {
    public int caps_offset;

    public @Unsigned int has_tt;

    public @Unsigned int has_synopsys_hc_bug;

    public @Unsigned int big_endian_desc;

    public @Unsigned int big_endian_mmio;

    public @Unsigned int no_io_watchdog;

    public @Unsigned int reset_on_resume;

    public @Unsigned int dma_mask_64;

    public @Unsigned int spurious_oc;

    public Ptr<?> power_on;

    public Ptr<?> power_off;

    public Ptr<?> power_suspend;

    public Ptr<?> pre_setup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_ohci_pdata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_ohci_pdata extends Struct {
    public @Unsigned int big_endian_desc;

    public @Unsigned int big_endian_mmio;

    public @Unsigned int no_big_frame_no;

    public @Unsigned int num_ports;

    public Ptr<?> power_on;

    public Ptr<?> power_off;

    public Ptr<?> power_suspend;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_string_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_string_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    @InlineUnion(52535)
    public @Unsigned @OriginalName("__le16") short legacy_padding;

    @InlineUnion(52535)
    public anon_member_of_anon_member_of_usb_string_descriptor anon2$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_debug_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_debug_descriptor extends Struct {
    public char bLength;

    public char bDescriptorType;

    public char bDebugInEndpoint;

    public char bDebugOutEndpoint;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct usb_role_switch"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class usb_role_switch extends Struct {
    public device dev;

    public lock_class_key key;

    public mutex lock;

    public Ptr<module> module;

    public usb_role role;

    public boolean registered;

    public Ptr<device> usb2_port;

    public Ptr<device> usb3_port;

    public Ptr<device> udc;

    public @OriginalName("usb_role_switch_set_t") Ptr<?> set;

    public @OriginalName("usb_role_switch_get_t") Ptr<?> get;

    public boolean allow_userspace_control;
  }
}
