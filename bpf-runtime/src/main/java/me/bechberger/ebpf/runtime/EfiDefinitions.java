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
 * Generated class for BPF runtime types that start with efi
 */
@java.lang.SuppressWarnings("unused")
public final class EfiDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __efi_call() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __efi_enter_virtual_mode() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __efi_mem_desc_lookup(@Unsigned long phys_addr, Ptr<efi_memory_desc_t> out_md) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __efi_memmap_init(Ptr<efi_memory_map_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long __efi_queue_work(efi_rts_ids id,
      Ptr<efi_rts_args> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __efi_soft_reserve_enabled() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_alloc_page_tables() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_apply_memmap_quirks() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_arch_mem_reserve(@Unsigned @OriginalName("phys_addr_t") long addr,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short efi_attr_is_visible(Ptr<kobject> kobj,
      Ptr<attribute> attr, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_bgrt_init(Ptr<acpi_table_header> table) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_call_acpi_prm_handler((long unsigned int (*)(long long unsigned int, void*))$arg1, $arg2, $arg3)")
  public static @Unsigned @OriginalName("efi_status_t") long efi_call_acpi_prm_handler(
      Ptr<?> handler_addr, @Unsigned long param_buffer_addr, Ptr<?> context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_call_rts(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_call_virt_check_flags($arg1, (const void *)$arg2)")
  public static void efi_call_virt_check_flags(@Unsigned long flags, Ptr<?> caller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long efi_call_virt_save_flags() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean efi_capsule_pending(Ptr<java.lang.Integer> reset_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_capsule_supported(@OriginalName("efi_guid_t") uuid_t guid,
      @Unsigned int flags, @Unsigned long size, Ptr<java.lang.Integer> reset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_capsule_update(Ptr<efi_capsule_header_t> capsule,
      Ptr<java.lang. @Unsigned @OriginalName("phys_addr_t") Long> pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_check_for_embedded_firmwares() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_check_md_for_embedded_firmware($arg1, (const struct efi_embedded_fw_desc *)$arg2)")
  public static int efi_check_md_for_embedded_firmware(Ptr<efi_memory_desc_t> md,
      Ptr<efi_embedded_fw_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_clean_memmap() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_config_parse_tables((const union {\n"
          + "  struct {\n"
          + "    struct {\n"
          + "      u8 b[16];\n"
          + "    } guid;\n"
          + "    void *table;\n"
          + "  };\n"
          + "  struct {\n"
          + "    struct {\n"
          + "      u8 b[16];\n"
          + "    } guid;\n"
          + "    unsigned int table;\n"
          + "  } mixed_mode;\n"
          + "} *)$arg1, $arg2, (const struct {\n"
          + "  struct {\n"
          + "    u8 b[16];\n"
          + "  } guid;\n"
          + "  long unsigned int *ptr;\n"
          + "  const const u8[16] name;\n"
          + "} *)$arg3)")
  public static int efi_config_parse_tables(Ptr<efi_config_table_t> config_tables, int count,
      Ptr<efi_config_table_type_t> arch_tables) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_crash_gracefully_on_page_fault(@Unsigned long phys_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_delete_dummy_variable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_dump_pagetable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> efi_earlycon_map(@Unsigned long start, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_earlycon_remap_fb() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_earlycon_reprobe() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_earlycon_scroll_up() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_earlycon_setup($arg1, (const u8 *)$arg2)")
  public static int efi_earlycon_setup(Ptr<earlycon_device> device, String opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_earlycon_unmap(Ptr<?> addr, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_earlycon_unmap_fb() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_earlycon_write($arg1, (const u8 *)$arg2, $arg3)")
  public static void efi_earlycon_write(Ptr<console> con, String str, @Unsigned int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_enter_virtual_mode() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_esrt_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_find_mirror() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_free_boot_services() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_get_device_by_path((const struct efi_dev_path**)$arg1, $arg2)")
  public static Ptr<device> efi_get_device_by_path(Ptr<Ptr<efi_dev_path>> node,
      Ptr<java.lang. @Unsigned Long> len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_get_embedded_fw((const u8 *)$arg1, (const u8**)$arg2, $arg3)")
  public static int efi_get_embedded_fw(String name, Ptr<Ptr<java.lang.Character>> data,
      Ptr<java.lang. @Unsigned Long> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_get_runtime_map_desc_size() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_get_runtime_map_size() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean efi_is_table_address(@Unsigned long phys_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_map_region(Ptr<efi_memory_desc_t> md) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_map_region_fixed(Ptr<efi_memory_desc_t> md) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> efi_map_regions(Ptr<java.lang.Integer> count,
      Ptr<java.lang.Integer> pg_shift) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_md_typeattr_format($arg1, $arg2, (const struct {\n"
          + "  unsigned int type;\n"
          + "  unsigned int pad;\n"
          + "  long long unsigned int phys_addr;\n"
          + "  long long unsigned int virt_addr;\n"
          + "  long long unsigned int num_pages;\n"
          + "  long long unsigned int attribute;\n"
          + "} *)$arg3)")
  public static String efi_md_typeattr_format(String buf, @Unsigned long size,
      Ptr<efi_memory_desc_t> md) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long efi_mem_attributes(@Unsigned long phys_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long efi_mem_desc_end(Ptr<efi_memory_desc_t> md) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_mem_desc_lookup(@Unsigned long phys_addr, Ptr<efi_memory_desc_t> out_md) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_mem_reserve(@Unsigned @OriginalName("phys_addr_t") long addr,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_mem_reserve_iomem(@Unsigned @OriginalName("phys_addr_t") long addr,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_mem_reserve_persistent(@Unsigned @OriginalName("phys_addr_t") long addr,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_mem_type(@Unsigned long phys_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memattr_apply_permissions(Ptr<mm_struct> mm,
      @OriginalName("efi_memattr_perm_setter") Ptr<?> fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memattr_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memblock_x86_reserve_range() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memmap_alloc(@Unsigned int num_entries, Ptr<efi_memory_map_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_memmap_entry_valid((const struct {\n"
          + "  unsigned int type;\n"
          + "  unsigned int pad;\n"
          + "  long long unsigned int phys_addr;\n"
          + "  long long unsigned int virt_addr;\n"
          + "  long long unsigned int num_pages;\n"
          + "  long long unsigned int attribute;\n"
          + "} *)$arg1, $arg2)")
  public static boolean efi_memmap_entry_valid(Ptr<efi_memory_desc_t> md, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memmap_init_early(Ptr<efi_memory_map_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memmap_init_late(@Unsigned @OriginalName("phys_addr_t") long addr,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_memmap_insert(Ptr<efi_memory_map> old_memmap, Ptr<?> buf,
      Ptr<efi_mem_range> mem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memmap_install(Ptr<efi_memory_map_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memmap_split_count(Ptr<efi_memory_desc_t> md, Ptr<range> range) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_memmap_unmap() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memreserve_map_root() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_memreserve_root_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_mokvar_entry_find((const u8 *)$arg1)")
  public static Ptr<efi_mokvar_table_entry> efi_mokvar_entry_find(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<efi_mokvar_table_entry> efi_mokvar_entry_next(
      Ptr<Ptr<efi_mokvar_table_entry>> mokvar_entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_mokvar_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_mokvar_sysfs_read($arg1, $arg2, (const struct bin_attribute *)$arg3, $arg4, $arg5, $arg6)")
  public static @OriginalName("ssize_t") long efi_mokvar_sysfs_read(Ptr<file> file,
      Ptr<kobject> kobj, Ptr<bin_attribute> bin_attr, String buf, @OriginalName("loff_t") long off,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_mokvar_table_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_native_runtime_setup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_partition(Ptr<parsed_partitions> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_power_off(Ptr<sys_off_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean efi_poweroff_required() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_print_memmap() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_query_variable_store(
      @Unsigned int attributes, @Unsigned long size, boolean nonblocking) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_rci2_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_reboot($arg1, (const u8 *)$arg2)")
  public static void efi_reboot(reboot_mode reboot_mode, String __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean efi_reboot_required() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_reserve_boot_services() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_reuse_config(@Unsigned long tables, int nr_tables) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean efi_runtime_disabled() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_runtime_map_copy(Ptr<?> buf, @Unsigned long bufsz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_runtime_map_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_runtime_update_mappings() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_set_secure_boot(efi_secureboot_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_set_virtual_address_map(
      @Unsigned long memory_map_size, @Unsigned long descriptor_size,
      @Unsigned int descriptor_version, Ptr<efi_memory_desc_t> virtual_map,
      @Unsigned long systab_phys) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_setup_page_tables(@Unsigned long pa_memmap, @Unsigned int num_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_shutdown_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_status_cmp_bsearch((const void *)$arg1, (const void *)$arg2)")
  public static int efi_status_cmp_bsearch(Ptr<?> key, Ptr<?> item) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_status_to_err(@Unsigned @OriginalName("efi_status_t") long status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)efi_status_to_str($arg1))")
  public static String efi_status_to_str(@Unsigned @OriginalName("efi_status_t") long status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_sync_low_kernel_mappings() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_systab_check_header((const struct {\n"
          + "  long long unsigned int signature;\n"
          + "  unsigned int revision;\n"
          + "  unsigned int headersize;\n"
          + "  unsigned int crc32;\n"
          + "  unsigned int reserved;\n"
          + "} *)$arg1)")
  public static int efi_systab_check_header(Ptr<efi_table_hdr_t> systab_hdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_systab_init(@Unsigned long phys) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("efi_systab_report_header((const struct {\n"
          + "  long long unsigned int signature;\n"
          + "  unsigned int revision;\n"
          + "  unsigned int headersize;\n"
          + "  unsigned int crc32;\n"
          + "  unsigned int reserved;\n"
          + "} *)$arg1, $arg2)")
  public static void efi_systab_report_header(Ptr<efi_table_hdr_t> systab_hdr,
      @Unsigned long fw_vendor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_get_next_high_mono_count(
      Ptr<java.lang. @Unsigned Integer> count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_get_next_variable(
      Ptr<java.lang. @Unsigned Long> name_size,
      Ptr<java.lang. @Unsigned @OriginalName("efi_char16_t") Short> name,
      Ptr<@OriginalName("efi_guid_t") uuid_t> vendor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_get_time(Ptr<efi_time_t> tm,
      Ptr<efi_time_cap_t> tc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_get_variable(
      Ptr<java.lang. @Unsigned @OriginalName("efi_char16_t") Short> name,
      Ptr<@OriginalName("efi_guid_t") uuid_t> vendor, Ptr<java.lang. @Unsigned Integer> attr,
      Ptr<java.lang. @Unsigned Long> data_size, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_get_wakeup_time(
      Ptr<java.lang. @OriginalName("efi_bool_t") Character> enabled,
      Ptr<java.lang. @OriginalName("efi_bool_t") Character> pending, Ptr<efi_time_t> tm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_query_capsule_caps(
      Ptr<Ptr<efi_capsule_header_t>> capsules, @Unsigned long count,
      Ptr<java.lang. @Unsigned Long> max_size, Ptr<java.lang.Integer> reset_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_query_variable_info(
      @Unsigned int attr, Ptr<java.lang. @Unsigned Long> storage_space,
      Ptr<java.lang. @Unsigned Long> remaining_space,
      Ptr<java.lang. @Unsigned Long> max_variable_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_query_variable_info_nonblocking(
      @Unsigned int attr, Ptr<java.lang. @Unsigned Long> storage_space,
      Ptr<java.lang. @Unsigned Long> remaining_space,
      Ptr<java.lang. @Unsigned Long> max_variable_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_thunk_reset_system(int reset_type,
      @Unsigned @OriginalName("efi_status_t") long status, @Unsigned long data_size,
      Ptr<java.lang. @Unsigned @OriginalName("efi_char16_t") Short> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void efi_thunk_runtime_setup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_set_time(
      Ptr<efi_time_t> tm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_set_variable(
      Ptr<java.lang. @Unsigned @OriginalName("efi_char16_t") Short> name,
      Ptr<@OriginalName("efi_guid_t") uuid_t> vendor, @Unsigned int attr, @Unsigned long data_size,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_set_variable_nonblocking(
      Ptr<java.lang. @Unsigned @OriginalName("efi_char16_t") Short> name,
      Ptr<@OriginalName("efi_guid_t") uuid_t> vendor, @Unsigned int attr, @Unsigned long data_size,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_set_virtual_address_map(
      @Unsigned long memory_map_size, @Unsigned long descriptor_size,
      @Unsigned int descriptor_version, Ptr<efi_memory_desc_t> virtual_map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_set_wakeup_time(
      @OriginalName("efi_bool_t") char enabled, Ptr<efi_time_t> tm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("efi_status_t") long efi_thunk_update_capsule(
      Ptr<Ptr<efi_capsule_header_t>> capsules, @Unsigned long count, @Unsigned long sg_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_tpm_eventlog_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int efi_update_mem_attr(Ptr<mm_struct> mm, Ptr<efi_memory_desc_t> md,
      boolean has_ibt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_table_hdr_t extends Struct {
    public @Unsigned long signature;

    public @Unsigned int revision;

    public @Unsigned int headersize;

    public @Unsigned int crc32;

    public @Unsigned int reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int type; unsigned int pad; long long unsigned int phys_addr; long long unsigned int virt_addr; long long unsigned int num_pages; long long unsigned int attribute; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_memory_desc_t extends Struct {
    public @Unsigned int type;

    public @Unsigned int pad;

    public @Unsigned long phys_addr;

    public @Unsigned long virt_addr;

    public @Unsigned long num_pages;

    public @Unsigned long attribute;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_capsule_header_t extends Struct {
    public @OriginalName("efi_guid_t") uuid_t guid;

    public @Unsigned int headersize;

    public @Unsigned int flags;

    public @Unsigned int imagesize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_time_t extends Struct {
    public @Unsigned short year;

    public char month;

    public char day;

    public char hour;

    public char minute;

    public char second;

    public char pad1;

    public @Unsigned int nanosecond;

    public short timezone;

    public char daylight;

    public char pad2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int resolution; unsigned int accuracy; u8 sets_to_zero; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_time_cap_t extends Struct {
    public @Unsigned int resolution;

    public @Unsigned int accuracy;

    public char sets_to_zero;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; unsigned int get_time; unsigned int set_time; unsigned int get_wakeup_time; unsigned int set_wakeup_time; unsigned int set_virtual_address_map; unsigned int convert_pointer; unsigned int get_variable; unsigned int get_next_variable; unsigned int set_variable; unsigned int get_next_high_mono_count; unsigned int reset_system; unsigned int update_capsule; unsigned int query_capsule_caps; unsigned int query_variable_info; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_runtime_services_32_t extends Struct {
    public efi_table_hdr_t hdr;

    public @Unsigned int get_time;

    public @Unsigned int set_time;

    public @Unsigned int get_wakeup_time;

    public @Unsigned int set_wakeup_time;

    public @Unsigned int set_virtual_address_map;

    public @Unsigned int convert_pointer;

    public @Unsigned int get_variable;

    public @Unsigned int get_next_variable;

    public @Unsigned int set_variable;

    public @Unsigned int get_next_high_mono_count;

    public @Unsigned int reset_system;

    public @Unsigned int update_capsule;

    public @Unsigned int query_capsule_caps;

    public @Unsigned int query_variable_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; long unsigned int (*get_time)(struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*, struct { unsigned int resolution; unsigned int accuracy; u8 sets_to_zero; }*); long unsigned int (*set_time)(struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*get_wakeup_time)(u8*, u8*, struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*set_wakeup_time)(u8, struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*set_virtual_address_map)(long unsigned int, long unsigned int, unsigned int, struct { unsigned int type; unsigned int pad; long long unsigned int phys_addr; long long unsigned int virt_addr; long long unsigned int num_pages; long long unsigned int attribute; }*); void *convert_pointer; long unsigned int (*get_variable)(short unsigned int*, struct { u8 b[16]; }*, unsigned int*, long unsigned int*, void*); long unsigned int (*get_next_variable)(long unsigned int*, short unsigned int*, struct { u8 b[16]; }*); long unsigned int (*set_variable)(short unsigned int*, struct { u8 b[16]; }*, unsigned int, long unsigned int, void*); long unsigned int (*get_next_high_mono_count)(unsigned int*); void (*reset_system)(int, long unsigned int, long unsigned int, short unsigned int*); long unsigned int (*update_capsule)(struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }**, long unsigned int, long unsigned int); long unsigned int (*query_capsule_caps)(struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }**, long unsigned int, long long unsigned int*, int*); long unsigned int (*query_variable_info)(unsigned int, long long unsigned int*, long long unsigned int*, long long unsigned int*); }; struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; unsigned int get_time; unsigned int set_time; unsigned int get_wakeup_time; unsigned int set_wakeup_time; unsigned int set_virtual_address_map; unsigned int convert_pointer; unsigned int get_variable; unsigned int get_next_variable; unsigned int set_variable; unsigned int get_next_high_mono_count; unsigned int reset_system; unsigned int update_capsule; unsigned int query_capsule_caps; unsigned int query_variable_info; } mixed_mode; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_runtime_services_t extends Union {
    public anon_member_of_efi_runtime_services_t anon0;

    public efi_runtime_services_32_t mixed_mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_memory_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_memory_map extends Struct {
    public @Unsigned @OriginalName("phys_addr_t") long phys_map;

    public Ptr<?> map;

    public Ptr<?> map_end;

    public int nr_map;

    public @Unsigned long desc_version;

    public @Unsigned long desc_size;

    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_info extends Struct {
    public @Unsigned int efi_loader_signature;

    public @Unsigned int efi_systab;

    public @Unsigned int efi_memdesc_size;

    public @Unsigned int efi_memdesc_version;

    public @Unsigned int efi_memmap;

    public @Unsigned int efi_memmap_size;

    public @Unsigned int efi_systab_hi;

    public @Unsigned int efi_memmap_hi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; unsigned int fw_vendor; unsigned int fw_revision; unsigned int con_in_handle; unsigned int con_in; unsigned int con_out_handle; unsigned int con_out; unsigned int stderr_handle; unsigned int stderr; unsigned int runtime; unsigned int boottime; unsigned int nr_tables; unsigned int tables; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_system_table_32_t extends Struct {
    public efi_table_hdr_t hdr;

    public @Unsigned int fw_vendor;

    public @Unsigned int fw_revision;

    public @Unsigned int con_in_handle;

    public @Unsigned int con_in;

    public @Unsigned int con_out_handle;

    public @Unsigned int con_out;

    public @Unsigned int stderr_handle;

    public @Unsigned int stderr;

    public @Unsigned int runtime;

    public @Unsigned int boottime;

    public @Unsigned int nr_tables;

    public @Unsigned int tables;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; long unsigned int fw_vendor; unsigned int fw_revision; long unsigned int con_in_handle; efi_simple_text_input_protocol *con_in; long unsigned int con_out_handle; efi_simple_text_output_protocol *con_out; long unsigned int stderr_handle; long unsigned int stderr; union { struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; long unsigned int (*get_time)(struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*, struct { unsigned int resolution; unsigned int accuracy; u8 sets_to_zero; }*); long unsigned int (*set_time)(struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*get_wakeup_time)(u8*, u8*, struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*set_wakeup_time)(u8, struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*set_virtual_address_map)(long unsigned int, long unsigned int, unsigned int, struct { unsigned int type; unsigned int pad; long long unsigned int phys_addr; long long unsigned int virt_addr; long long unsigned int num_pages; long long unsigned int attribute; }*); void *convert_pointer; long unsigned int (*get_variable)(short unsigned int*, struct { u8 b[16]; }*, unsigned int*, long unsigned int*, void*); long unsigned int (*get_next_variable)(long unsigned int*, short unsigned int*, struct { u8 b[16]; }*); long unsigned int (*set_variable)(short unsigned int*, struct { u8 b[16]; }*, unsigned int, long unsigned int, void*); long unsigned int (*get_next_high_mono_count)(unsigned int*); void (*reset_system)(int, long unsigned int, long unsigned int, short unsigned int*); long unsigned int (*update_capsule)(struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }**, long unsigned int, long unsigned int); long unsigned int (*query_capsule_caps)(struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }**, long unsigned int, long long unsigned int*, int*); long unsigned int (*query_variable_info)(unsigned int, long long unsigned int*, long long unsigned int*, long long unsigned int*); }; struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; unsigned int get_time; unsigned int set_time; unsigned int get_wakeup_time; unsigned int set_wakeup_time; unsigned int set_virtual_address_map; unsigned int convert_pointer; unsigned int get_variable; unsigned int get_next_variable; unsigned int set_variable; unsigned int get_next_high_mono_count; unsigned int reset_system; unsigned int update_capsule; unsigned int query_capsule_caps; unsigned int query_variable_info; } mixed_mode; } *runtime; efi_boot_services *boottime; long unsigned int nr_tables; long unsigned int tables; }; struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; unsigned int fw_vendor; unsigned int fw_revision; unsigned int con_in_handle; unsigned int con_in; unsigned int con_out_handle; unsigned int con_out; unsigned int stderr_handle; unsigned int stderr; unsigned int runtime; unsigned int boottime; unsigned int nr_tables; unsigned int tables; } mixed_mode; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_system_table_t extends Union {
    public anon_member_of_efi_system_table_t anon0;

    public efi_system_table_32_t mixed_mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum efi_secureboot_mode"
  )
  public enum efi_secureboot_mode implements Enum<efi_secureboot_mode>, TypedEnum<efi_secureboot_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code efi_secureboot_mode_unset = 0}
     */
    @EnumMember(
        value = 0L,
        name = "efi_secureboot_mode_unset"
    )
    efi_secureboot_mode_unset,

    /**
     * {@code efi_secureboot_mode_unknown = 1}
     */
    @EnumMember(
        value = 1L,
        name = "efi_secureboot_mode_unknown"
    )
    efi_secureboot_mode_unknown,

    /**
     * {@code efi_secureboot_mode_disabled = 2}
     */
    @EnumMember(
        value = 2L,
        name = "efi_secureboot_mode_disabled"
    )
    efi_secureboot_mode_disabled,

    /**
     * {@code efi_secureboot_mode_enabled = 3}
     */
    @EnumMember(
        value = 3L,
        name = "efi_secureboot_mode_enabled"
    )
    efi_secureboot_mode_enabled
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; long long unsigned int fw_vendor; unsigned int fw_revision; unsigned int __pad1; long long unsigned int con_in_handle; long long unsigned int con_in; long long unsigned int con_out_handle; long long unsigned int con_out; long long unsigned int stderr_handle; long long unsigned int stderr; long long unsigned int runtime; long long unsigned int boottime; unsigned int nr_tables; unsigned int __pad2; long long unsigned int tables; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_system_table_64_t extends Struct {
    public efi_table_hdr_t hdr;

    public @Unsigned long fw_vendor;

    public @Unsigned int fw_revision;

    public @Unsigned int __pad1;

    public @Unsigned long con_in_handle;

    public @Unsigned long con_in;

    public @Unsigned long con_out_handle;

    public @Unsigned long con_out;

    public @Unsigned long stderr_handle;

    public @Unsigned long stderr;

    public @Unsigned long runtime;

    public @Unsigned long boottime;

    public @Unsigned int nr_tables;

    public @Unsigned int __pad2;

    public @Unsigned long tables;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_setup_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_setup_data extends Struct {
    public @Unsigned long fw_vendor;

    public @Unsigned long __unused;

    public @Unsigned long tables;

    public @Unsigned long smbios;

    public @Unsigned long @Size(8) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_memory_map_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_memory_map_data extends Struct {
    public @Unsigned @OriginalName("phys_addr_t") long phys_map;

    public @Unsigned long size;

    public @Unsigned long desc_version;

    public @Unsigned long desc_size;

    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_mem_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_mem_range extends Struct {
    public range range;

    public @Unsigned long attribute;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { u8 b[16]; } guid; long long unsigned int table; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_config_table_64_t extends Struct {
    public @OriginalName("efi_guid_t") uuid_t guid;

    public @Unsigned long table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum efi_rts_ids"
  )
  public enum efi_rts_ids implements Enum<efi_rts_ids>, TypedEnum<efi_rts_ids, java.lang. @Unsigned Integer> {
    /**
     * {@code EFI_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "EFI_NONE"
    )
    EFI_NONE,

    /**
     * {@code EFI_GET_TIME = 1}
     */
    @EnumMember(
        value = 1L,
        name = "EFI_GET_TIME"
    )
    EFI_GET_TIME,

    /**
     * {@code EFI_SET_TIME = 2}
     */
    @EnumMember(
        value = 2L,
        name = "EFI_SET_TIME"
    )
    EFI_SET_TIME,

    /**
     * {@code EFI_GET_WAKEUP_TIME = 3}
     */
    @EnumMember(
        value = 3L,
        name = "EFI_GET_WAKEUP_TIME"
    )
    EFI_GET_WAKEUP_TIME,

    /**
     * {@code EFI_SET_WAKEUP_TIME = 4}
     */
    @EnumMember(
        value = 4L,
        name = "EFI_SET_WAKEUP_TIME"
    )
    EFI_SET_WAKEUP_TIME,

    /**
     * {@code EFI_GET_VARIABLE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "EFI_GET_VARIABLE"
    )
    EFI_GET_VARIABLE,

    /**
     * {@code EFI_GET_NEXT_VARIABLE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "EFI_GET_NEXT_VARIABLE"
    )
    EFI_GET_NEXT_VARIABLE,

    /**
     * {@code EFI_SET_VARIABLE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "EFI_SET_VARIABLE"
    )
    EFI_SET_VARIABLE,

    /**
     * {@code EFI_QUERY_VARIABLE_INFO = 8}
     */
    @EnumMember(
        value = 8L,
        name = "EFI_QUERY_VARIABLE_INFO"
    )
    EFI_QUERY_VARIABLE_INFO,

    /**
     * {@code EFI_GET_NEXT_HIGH_MONO_COUNT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "EFI_GET_NEXT_HIGH_MONO_COUNT"
    )
    EFI_GET_NEXT_HIGH_MONO_COUNT,

    /**
     * {@code EFI_RESET_SYSTEM = 10}
     */
    @EnumMember(
        value = 10L,
        name = "EFI_RESET_SYSTEM"
    )
    EFI_RESET_SYSTEM,

    /**
     * {@code EFI_UPDATE_CAPSULE = 11}
     */
    @EnumMember(
        value = 11L,
        name = "EFI_UPDATE_CAPSULE"
    )
    EFI_UPDATE_CAPSULE,

    /**
     * {@code EFI_QUERY_CAPSULE_CAPS = 12}
     */
    @EnumMember(
        value = 12L,
        name = "EFI_QUERY_CAPSULE_CAPS"
    )
    EFI_QUERY_CAPSULE_CAPS,

    /**
     * {@code EFI_ACPI_PRM_HANDLER = 13}
     */
    @EnumMember(
        value = 13L,
        name = "EFI_ACPI_PRM_HANDLER"
    )
    EFI_ACPI_PRM_HANDLER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_runtime_work"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_runtime_work extends Struct {
    public Ptr<efi_rts_args> args;

    public @Unsigned @OriginalName("efi_status_t") long status;

    public work_struct work;

    public efi_rts_ids efi_rts_id;

    public completion efi_rts_comp;

    public Ptr<?> caller;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { u8 b[16]; } guid; unsigned int table; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_config_table_32_t extends Struct {
    public @OriginalName("efi_guid_t") uuid_t guid;

    public @Unsigned int table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { u8 b[16]; } guid; void *table; }; struct { struct { u8 b[16]; } guid; unsigned int table; } mixed_mode; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_config_table_t extends Union {
    public anon_member_of_efi_config_table_t anon0;

    public efi_config_table_32_t mixed_mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { u8 b[16]; } guid; long unsigned int *ptr; const const u8[16] name; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_config_table_type_t extends Struct {
    public @OriginalName("efi_guid_t") uuid_t guid;

    public Ptr<java.lang. @Unsigned Long> ptr;

    public char @Size(16) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_runtime_map_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_runtime_map_entry extends Struct {
    public efi_memory_desc_t md;

    public kobject kobj;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_variable"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_variable extends Struct {
    public @Unsigned @OriginalName("efi_char16_t") short @Size(512) [] VariableName;

    public @OriginalName("efi_guid_t") uuid_t VendorGuid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_generic_dev_path"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_generic_dev_path extends Struct {
    public char type;

    public char sub_type;

    public @Unsigned short length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_mokvar_table_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_mokvar_table_entry extends Struct {
    public char @Size(256) [] name;

    public @Unsigned long data_size;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { u8 b[16]; } signature_owner; u8 signature_data[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_signature_data_t extends Struct {
    public @OriginalName("efi_guid_t") uuid_t signature_owner;

    public char @Size(0) [] signature_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { u8 b[16]; } signature_type; unsigned int signature_list_size; unsigned int signature_header_size; unsigned int signature_size; u8 signature_header[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_signature_list_t extends Struct {
    public @OriginalName("efi_guid_t") uuid_t signature_type;

    public @Unsigned int signature_list_size;

    public @Unsigned int signature_header_size;

    public @Unsigned int signature_size;

    public char @Size(0) [] signature_header;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_tcg2_final_events_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_tcg2_final_events_table extends Struct {
    public @Unsigned long version;

    public @Unsigned long nr_events;

    public char @Size(0) [] events;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_unaccepted_memory"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_unaccepted_memory extends Struct {
    public @Unsigned int version;

    public @Unsigned int unit_size;

    public @Unsigned long phys_base;

    public @Unsigned long size;

    public @Unsigned long @Size(0) [] bitmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int version; short unsigned int length; unsigned int runtime_services_supported; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_rt_properties_table_t extends Struct {
    public @Unsigned short version;

    public @Unsigned short length;

    public @Unsigned int runtime_services_supported;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_error_code"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_error_code extends Struct {
    public @Unsigned @OriginalName("efi_status_t") long status;

    public int errno;

    public String description;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int version; unsigned int num_entries; unsigned int desc_size; unsigned int flags; struct { unsigned int type; unsigned int pad; long long unsigned int phys_addr; long long unsigned int virt_addr; long long unsigned int num_pages; long long unsigned int attribute; } entry[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_memory_attributes_table_t extends Struct {
    public @Unsigned int version;

    public @Unsigned int num_entries;

    public @Unsigned int desc_size;

    public @Unsigned int flags;

    public efi_memory_desc_t @Size(0) [] entry;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int length; long long unsigned int data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_capsule_block_desc_t extends Struct {
    public @Unsigned long length;

    public @Unsigned long data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_system_resource_entry_v1"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_system_resource_entry_v1 extends Struct {
    public @OriginalName("efi_guid_t") uuid_t fw_class;

    public @Unsigned int fw_type;

    public @Unsigned int fw_version;

    public @Unsigned int lowest_supported_fw_version;

    public @Unsigned int capsule_flags;

    public @Unsigned int last_attempt_version;

    public @Unsigned int last_attempt_status;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_system_resource_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_system_resource_table extends Struct {
    public @Unsigned int fw_resource_count;

    public @Unsigned int fw_resource_count_max;

    public @Unsigned long fw_resource_version;

    public char @Size(0) [] entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union efi_rts_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_rts_args extends Union {
    public GET_TIME_of_efi_rts_args GET_TIME;

    public SET_TIME_of_efi_rts_args SET_TIME;

    public GET_WAKEUP_TIME_of_efi_rts_args GET_WAKEUP_TIME;

    public SET_WAKEUP_TIME_of_efi_rts_args SET_WAKEUP_TIME;

    public GET_VARIABLE_of_efi_rts_args GET_VARIABLE;

    public GET_NEXT_VARIABLE_of_efi_rts_args GET_NEXT_VARIABLE;

    public SET_VARIABLE_of_efi_rts_args SET_VARIABLE;

    public QUERY_VARIABLE_INFO_of_efi_rts_args QUERY_VARIABLE_INFO;

    public GET_NEXT_HIGH_MONO_COUNT_of_efi_rts_args GET_NEXT_HIGH_MONO_COUNT;

    public UPDATE_CAPSULE_of_efi_rts_args UPDATE_CAPSULE;

    public QUERY_CAPSULE_CAPS_of_efi_rts_args QUERY_CAPSULE_CAPS;

    public ACPI_PRM_HANDLER_of_efi_rts_args ACPI_PRM_HANDLER;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_acpi_dev_path"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_acpi_dev_path extends Struct {
    public efi_generic_dev_path header;

    public @Unsigned int hid;

    public @Unsigned int uid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_pci_dev_path"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_pci_dev_path extends Struct {
    public efi_generic_dev_path header;

    public char fn;

    public char dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_vendor_dev_path"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_vendor_dev_path extends Struct {
    public efi_generic_dev_path header;

    public @OriginalName("efi_guid_t") uuid_t vendorguid;

    public char @Size(0) [] vendordata;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_rel_offset_dev_path"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_rel_offset_dev_path extends Struct {
    public efi_generic_dev_path header;

    public @Unsigned int reserved;

    public @Unsigned long starting_offset;

    public @Unsigned long ending_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_dev_path"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_dev_path extends Struct {
    @InlineUnion(55372)
    public efi_generic_dev_path header;

    @InlineUnion(55372)
    public efi_acpi_dev_path acpi;

    @InlineUnion(55372)
    public efi_pci_dev_path pci;

    @InlineUnion(55372)
    public efi_vendor_dev_path vendor;

    @InlineUnion(55372)
    public efi_rel_offset_dev_path rel_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_embedded_fw"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_embedded_fw extends Struct {
    public list_head list;

    public String name;

    public Ptr<java.lang.Character> data;

    public @Unsigned long length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_embedded_fw_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_embedded_fw_desc extends Struct {
    public String name;

    public char @Size(8) [] prefix;

    public @Unsigned int length;

    public char @Size(32) [] sha256;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct efi_mokvar_sysfs_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class efi_mokvar_sysfs_attr extends Struct {
    public bin_attribute bin_attr;

    public list_head node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int *name; struct { u8 b[16]; } *vendor; unsigned int *attr; long unsigned int *data_size; void *data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class GET_VARIABLE_of_efi_rts_args extends Struct {
    public Ptr<java.lang. @Unsigned @OriginalName("efi_char16_t") Short> name;

    public Ptr<@OriginalName("efi_guid_t") uuid_t> vendor;

    public Ptr<java.lang. @Unsigned Integer> attr;

    public Ptr<java.lang. @Unsigned Long> data_size;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int *name_size; short unsigned int *name; struct { u8 b[16]; } *vendor; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class GET_NEXT_VARIABLE_of_efi_rts_args extends Struct {
    public Ptr<java.lang. @Unsigned Long> name_size;

    public Ptr<java.lang. @Unsigned @OriginalName("efi_char16_t") Short> name;

    public Ptr<@OriginalName("efi_guid_t") uuid_t> vendor;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int (*acpi_prm_handler)(long long unsigned int, void*); long long unsigned int param_buffer_addr; void *context; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ACPI_PRM_HANDLER_of_efi_rts_args extends Struct {
    public Ptr<?> acpi_prm_handler;

    public @Unsigned long param_buffer_addr;

    public Ptr<?> context;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 enable; struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; } *time; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class SET_WAKEUP_TIME_of_efi_rts_args extends Struct {
    public @OriginalName("efi_bool_t") char enable;

    public Ptr<efi_time_t> time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 *enabled; u8 *pending; struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; } *time; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class GET_WAKEUP_TIME_of_efi_rts_args extends Struct {
    public Ptr<java.lang. @OriginalName("efi_bool_t") Character> enabled;

    public Ptr<java.lang. @OriginalName("efi_bool_t") Character> pending;

    public Ptr<efi_time_t> time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; } *time; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class SET_TIME_of_efi_rts_args extends Struct {
    public Ptr<efi_time_t> time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; } **capsules; long unsigned int count; long unsigned int sg_list; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class UPDATE_CAPSULE_of_efi_rts_args extends Struct {
    public Ptr<Ptr<efi_capsule_header_t>> capsules;

    public @Unsigned long count;

    public @Unsigned long sg_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; } *time; struct { unsigned int resolution; unsigned int accuracy; u8 sets_to_zero; } *capabilities; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class GET_TIME_of_efi_rts_args extends Struct {
    public Ptr<efi_time_t> time;

    public Ptr<efi_time_cap_t> capabilities;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int *high_count; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class GET_NEXT_HIGH_MONO_COUNT_of_efi_rts_args extends Struct {
    public Ptr<java.lang. @Unsigned Integer> high_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int *name; struct { u8 b[16]; } *vendor; unsigned int attr; long unsigned int data_size; void *data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class SET_VARIABLE_of_efi_rts_args extends Struct {
    public Ptr<java.lang. @Unsigned @OriginalName("efi_char16_t") Short> name;

    public Ptr<@OriginalName("efi_guid_t") uuid_t> vendor;

    public @Unsigned int attr;

    public @Unsigned long data_size;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; } **capsules; long unsigned int count; long long unsigned int *max_size; int *reset_type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class QUERY_CAPSULE_CAPS_of_efi_rts_args extends Struct {
    public Ptr<Ptr<efi_capsule_header_t>> capsules;

    public @Unsigned long count;

    public Ptr<java.lang. @Unsigned Long> max_size;

    public Ptr<java.lang.Integer> reset_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int attr; long long unsigned int *storage_space; long long unsigned int *remaining_space; long long unsigned int *max_variable_size; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class QUERY_VARIABLE_INFO_of_efi_rts_args extends Struct {
    public @Unsigned int attr;

    public Ptr<java.lang. @Unsigned Long> storage_space;

    public Ptr<java.lang. @Unsigned Long> remaining_space;

    public Ptr<java.lang. @Unsigned Long> max_variable_size;
  }
}
